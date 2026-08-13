// Package proxy is a local forward proxy that MITMs TLS so a scanning tool
// (nuclei, httpx, ...) pointed at it via -proxy has each outbound request
// relayed through a rotated jump-host Lambda. API Gateway / Lambda cannot act
// as a forward proxy themselves (no CONNECT tunnelling), so this local piece
// terminates TLS, reads each request in the clear, and turns it into a
// lambda.Invoke. Rotation across regions happens per request.
package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"

	"github.com/intruderlabs/tmt/internal/wire"
)

// Invoker relays one request through a single backend (one region). The proxy
// holds one per region and rotates across them; a fake satisfies it in tests.
type Invoker interface {
	Invoke(ctx context.Context, req wire.Request) (wire.Response, error)
}

// Proxy is an http.Handler: plug it into an http.Server the caller owns.
type Proxy struct {
	backends []Invoker
	next     atomic.Uint64

	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	caDER  []byte
	caPEM  []byte

	certs sync.Map // host -> *tls.Certificate
}

// New builds a Proxy with a freshly generated in-memory CA and the given
// backends (one per region, rotated per request).
func New(backends []Invoker) (*Proxy, error) {
	if len(backends) == 0 {
		return nil, fmt.Errorf("proxy needs at least one backend")
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating CA key: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "TMT Local MITM CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("creating CA cert: %w", err)
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parsing CA cert: %w", err)
	}
	return &Proxy{
		backends: backends,
		caCert:   caCert,
		caKey:    caKey,
		caDER:    der,
		caPEM:    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}, nil
}

// CAPEM returns the CA certificate in PEM form, for tools that verify TLS
// (pass it via SSL_CERT_FILE / --cacert). nuclei typically skips verification.
func (p *Proxy) CAPEM() []byte { return p.caPEM }

func (p *Proxy) pick() Invoker {
	i := p.next.Add(1) - 1
	return p.backends[i%uint64(len(p.backends))]
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	p.handleHTTP(w, r)
}

// handleHTTP serves a plain-HTTP (absolute-URL) proxied request.
func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	resp := p.roundtrip(r.Context(), r)
	defer resp.Body.Close()
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// handleConnect terminates the tunnel's TLS with a minted cert, then relays
// each decrypted request through a rotated backend.
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	connectHost := stripPort(r.Host)
	tlsConn := tls.Server(clientConn, &tls.Config{
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host := chi.ServerName
			if host == "" {
				host = connectHost
			}
			return p.certFor(host)
		},
	})
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	defer tlsConn.Close()

	reader := bufio.NewReader(tlsConn)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			return // EOF or malformed: tunnel done
		}
		req.URL.Scheme = "https"
		if req.Host != "" {
			req.URL.Host = req.Host
		} else {
			req.URL.Host = connectHost
		}
		resp := p.roundtrip(context.Background(), req)
		werr := resp.Write(tlsConn)
		resp.Body.Close()
		if werr != nil || resp.Close {
			return
		}
	}
}

// roundtrip turns an *http.Request into a wire.Request, invokes a rotated
// backend, and returns an *http.Response (always non-nil; errors become 502).
func (p *Proxy) roundtrip(ctx context.Context, req *http.Request) *http.Response {
	wreq, err := toWire(req)
	if err != nil {
		return errResponse("building request: " + err.Error())
	}
	wresp, err := p.pick().Invoke(ctx, wreq)
	if err != nil {
		return errResponse("invoke: " + err.Error())
	}
	if wresp.Err != "" {
		return errResponse(wresp.Err)
	}
	return fromWire(wresp)
}

// toWire builds the Lambda payload from a request, dropping hop-by-hop headers.
func toWire(req *http.Request) (wire.Request, error) {
	var b64 string
	if req.Body != nil {
		data, err := io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return wire.Request{}, err
		}
		if len(data) > 0 {
			b64 = base64.StdEncoding.EncodeToString(data)
		}
	}
	h := make(map[string][]string, len(req.Header))
	for k, v := range req.Header {
		switch http.CanonicalHeaderKey(k) {
		case "Proxy-Connection", "Connection", "Keep-Alive":
			continue
		}
		h[k] = v
	}
	return wire.Request{Method: req.Method, URL: req.URL.String(), Header: h, BodyB64: b64}, nil
}

// fromWire builds a client-facing response from the Lambda reply.
func fromWire(resp wire.Response) *http.Response {
	var data []byte
	if resp.BodyB64 != "" {
		data, _ = base64.StdEncoding.DecodeString(resp.BodyB64)
	}
	h := http.Header(resp.Header)
	if h == nil {
		h = http.Header{}
	}
	// Length/encoding are re-derived from the body we hand to Write.
	h.Del("Content-Length")
	h.Del("Transfer-Encoding")
	return &http.Response{
		StatusCode:    resp.Status,
		Status:        fmt.Sprintf("%d %s", resp.Status, http.StatusText(resp.Status)),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        h,
		Body:          io.NopCloser(bytes.NewReader(data)),
		ContentLength: int64(len(data)),
	}
}

func errResponse(msg string) *http.Response {
	body := "tmt jump error: " + msg
	return &http.Response{
		StatusCode:    http.StatusBadGateway,
		Status:        "502 Bad Gateway",
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": {"text/plain"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
}

// certFor returns a leaf cert for host, minting and caching one on first use.
func (p *Proxy) certFor(host string) (*tls.Certificate, error) {
	if c, ok := p.certs.Load(host); ok {
		return c.(*tls.Certificate), nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		return nil, err
	}
	cert := &tls.Certificate{Certificate: [][]byte{der, p.caDER}, PrivateKey: key}
	actual, _ := p.certs.LoadOrStore(host, cert)
	return actual.(*tls.Certificate), nil
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return big.NewInt(time.Now().UnixNano())
	}
	return n
}

func stripPort(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

// lambdaInvoker is the real Invoker: it calls lambda.Invoke on one region's
// function.
type lambdaInvoker struct {
	client *lambda.Client
	fn     string
}

// NewLambdaInvoker builds an Invoker backed by a region's Lambda client.
func NewLambdaInvoker(client *lambda.Client, funcName string) Invoker {
	return &lambdaInvoker{client: client, fn: funcName}
}

func (l *lambdaInvoker) Invoke(ctx context.Context, req wire.Request) (wire.Response, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return wire.Response{}, err
	}
	out, err := l.client.Invoke(ctx, &lambda.InvokeInput{
		FunctionName: aws.String(l.fn),
		Payload:      payload,
	})
	if err != nil {
		return wire.Response{}, err
	}
	if out.FunctionError != nil {
		return wire.Response{}, fmt.Errorf("lambda error: %s", string(out.Payload))
	}
	var resp wire.Response
	if err := json.Unmarshal(out.Payload, &resp); err != nil {
		return wire.Response{}, fmt.Errorf("decoding lambda reply: %w", err)
	}
	return resp, nil
}
