// Package wire holds the request/response payload exchanged between the local
// MITM proxy (internal/proxy) and the jump-host Lambda (cmd/lambdafn). Bodies
// are base64-encoded so arbitrary binary payloads survive the JSON round-trip.
package wire

// Request is what the proxy sends to the Lambda: the outbound HTTP call to make.
type Request struct {
	Method  string              `json:"method"`
	URL     string              `json:"url"`
	Header  map[string][]string `json:"header,omitempty"`
	BodyB64 string              `json:"body_b64,omitempty"`
}

// Response is what the Lambda returns: the target's reply, or Err set on failure.
type Response struct {
	Status  int                 `json:"status"`
	Header  map[string][]string `json:"header,omitempty"`
	BodyB64 string              `json:"body_b64,omitempty"`
	Err     string              `json:"err,omitempty"`
}
