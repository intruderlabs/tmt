// Command lambdafn is the TMT jump-host Lambda: a target-agnostic egress
// function. It receives an HTTP request to make (wire.Request), performs it
// from within AWS, and returns the target's response (wire.Response). One
// copy is deployed per region; the local MITM proxy rotates Invoke calls
// across regions so outbound traffic egresses from AWS's shared IP pool.
package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/lambda"

	"github.com/intruderlabs/tmt/internal/wire"
)

// maxBody caps the raw response body. Lambda's synchronous Invoke response is
// limited to 6 MB; base64 inflates by ~33%, so 4 MB of raw body keeps the
// encoded JSON safely under the ceiling.
// ponytail: hard 4MB cap; add Function URL response streaming if targets need more.
const maxBody = 4 << 20

// client is reused across warm invocations. No redirect following: the proxy
// (and the scanning tool) should see redirects as the target sent them.
var client = &http.Client{
	Timeout: 30 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func handle(ctx context.Context, in wire.Request) (wire.Response, error) {
	var body io.Reader
	if in.BodyB64 != "" {
		raw, err := base64.StdEncoding.DecodeString(in.BodyB64)
		if err != nil {
			return wire.Response{Err: "decoding request body: " + err.Error()}, nil
		}
		body = strings.NewReader(string(raw))
	}

	req, err := http.NewRequestWithContext(ctx, in.Method, in.URL, body)
	if err != nil {
		return wire.Response{Err: "building request: " + err.Error()}, nil
	}
	req.Header = in.Header

	resp, err := client.Do(req)
	if err != nil {
		return wire.Response{Err: "calling target: " + err.Error()}, nil
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return wire.Response{Err: "reading response: " + err.Error()}, nil
	}
	if len(raw) > maxBody {
		return wire.Response{Err: fmt.Sprintf("response exceeds %d-byte limit", maxBody)}, nil
	}

	return wire.Response{
		Status:  resp.StatusCode,
		Header:  resp.Header,
		BodyB64: base64.StdEncoding.EncodeToString(raw),
	}, nil
}

func main() {
	lambda.Start(handle)
}
