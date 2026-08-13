package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/intruderlabs/tmt/internal/wire"
)

// fakeInvoker records requests and appends its region to a shared log, so
// tests can assert both payload contents and rotation order.
type fakeInvoker struct {
	region string
	log    *[]string
	got    []wire.Request
}

func (f *fakeInvoker) Invoke(_ context.Context, req wire.Request) (wire.Response, error) {
	f.got = append(f.got, req)
	*f.log = append(*f.log, f.region)
	return wire.Response{Status: 200, BodyB64: base64.StdEncoding.EncodeToString([]byte("ok-" + f.region))}, nil
}

func TestNew_RejectsNoBackends(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("expected error with zero backends")
	}
}

func TestRoundtrip_RotatesBackends(t *testing.T) {
	var log []string
	a := &fakeInvoker{region: "a", log: &log}
	b := &fakeInvoker{region: "b", log: &log}
	c := &fakeInvoker{region: "c", log: &log}
	p, err := New([]Invoker{a, b, c})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for i := 0; i < 6; i++ {
		req := httptest.NewRequest("GET", "http://example.com/", nil)
		resp := p.roundtrip(context.Background(), req)
		resp.Body.Close()
	}

	if want := []string{"a", "b", "c", "a", "b", "c"}; strings.Join(log, ",") != strings.Join(want, ",") {
		t.Fatalf("rotation order = %v, want %v", log, want)
	}
}

// TestConnect_MITMTunnel exercises the full HTTPS path: a client using the
// proxy issues CONNECT, the proxy mints a cert and terminates TLS, reads the
// decrypted request, and relays it through a backend. The client trusts the
// proxy's CA so the minted cert validates.
func TestConnect_MITMTunnel(t *testing.T) {
	var log []string
	inv := &fakeInvoker{region: "a", log: &log}
	p, err := New([]Invoker{inv})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := httptest.NewServer(p)
	defer srv.Close()

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(p.CAPEM()) {
		t.Fatal("failed to load proxy CA")
	}
	proxyURL, _ := url.Parse(srv.URL)
	client := &http.Client{Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}}

	resp, err := client.Get("https://example.com/foo")
	if err != nil {
		t.Fatalf("client.Get through MITM proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok-a" {
		t.Fatalf("body = %q, want ok-a", body)
	}
	if len(inv.got) != 1 || inv.got[0].URL != "https://example.com/foo" {
		t.Fatalf("backend saw %+v", inv.got)
	}
}

func TestToWire_BuildsPayload(t *testing.T) {
	var log []string
	inv := &fakeInvoker{region: "a", log: &log}
	p, err := New([]Invoker{inv})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest("POST", "http://example.com/path?q=1", strings.NewReader("hello"))
	req.Header.Set("X-Custom", "v")
	req.Header.Set("Proxy-Connection", "keep-alive") // hop-by-hop, must be dropped

	resp := p.roundtrip(context.Background(), req)
	resp.Body.Close()

	if len(inv.got) != 1 {
		t.Fatalf("expected 1 invocation, got %d", len(inv.got))
	}
	w := inv.got[0]
	if w.Method != "POST" {
		t.Errorf("method = %q", w.Method)
	}
	if w.URL != "http://example.com/path?q=1" {
		t.Errorf("url = %q", w.URL)
	}
	body, _ := base64.StdEncoding.DecodeString(w.BodyB64)
	if string(body) != "hello" {
		t.Errorf("body = %q", body)
	}
	if got := w.Header["X-Custom"]; len(got) != 1 || got[0] != "v" {
		t.Errorf("X-Custom header = %v", got)
	}
	if _, ok := w.Header["Proxy-Connection"]; ok {
		t.Error("Proxy-Connection should have been dropped")
	}
}
