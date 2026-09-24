// Package httpfetch holds the outbound HTTP rules every protocol fetch in the
// wallet shares: redirects are not followed, response bodies are read up to a
// limit, and media types are compared after parsing.
//
// Server-side request forgery control (which hosts may be dialled) is not
// decided here. It belongs to the http.Client the integrator injects.
package httpfetch

import (
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/trustknots/vcknots/wallet/common"
)

const (
	// DefaultBodyLimit bounds metadata, statements, tokens and other small
	// protocol documents.
	DefaultBodyLimit int64 = 64 << 10
	// CredentialBodyLimit bounds responses that carry credentials, whose size
	// grows with batch issuance and embedded status or evidence.
	CredentialBodyLimit int64 = 1 << 20
	// DefaultTimeout is the timeout of a client this package creates.
	DefaultTimeout = 30 * time.Second
)

// ErrBodyTooLarge is returned when a response declares or delivers more bytes
// than the caller's limit.
var ErrBodyTooLarge = common.NewCodedError("response_body_too_large", "response body exceeds the size limit")

// NewClient returns a client with DefaultTimeout that does not follow
// redirects.
func NewClient() *http.Client {
	return &http.Client{Timeout: DefaultTimeout, CheckRedirect: refuseRedirect}
}

// NoRedirect returns a copy of client that does not follow redirects: the
// redirect response itself is returned to the caller, which treats it as the
// non-2xx answer it is. The caller's client is not modified. A nil client
// yields NewClient().
func NoRedirect(client *http.Client) *http.Client {
	if client == nil {
		return NewClient()
	}
	clone := *client
	clone.CheckRedirect = refuseRedirect
	return &clone
}

func refuseRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

// ReadLimited reads the response body, refusing one that declares or delivers
// more than limit bytes. A declared Content-Length is checked before anything
// is read; the read itself is bounded too, because the declaration may be
// absent or untrue.
func ReadLimited(response *http.Response, limit int64) ([]byte, error) {
	if declared := response.Header.Get("Content-Length"); declared != "" {
		length, err := strconv.ParseInt(declared, 10, 64)
		if err != nil || length < 0 {
			return nil, fmt.Errorf("response has an invalid Content-Length %q", declared)
		}
		if length > limit {
			return nil, fmt.Errorf("%w: %d bytes declared, limit %d", ErrBodyTooLarge, length, limit)
		}
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read the response body: %w", err)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("%w: limit %d", ErrBodyTooLarge, limit)
	}
	return body, nil
}

// MediaType returns the lower-cased media type of the Content-Type header
// without parameters, or "" when the header is absent or malformed.
func MediaType(header http.Header) string {
	value := header.Get("Content-Type")
	if value == "" {
		return ""
	}
	mediaType, _, err := mime.ParseMediaType(value)
	if err != nil {
		return ""
	}
	return strings.ToLower(mediaType)
}

// MediaTypeIs reports whether the Content-Type header names one of the wanted
// media types exactly (case-insensitively, parameters ignored).
func MediaTypeIs(header http.Header, want ...string) bool {
	got := MediaType(header)
	if got == "" {
		return false
	}
	for _, candidate := range want {
		if strings.EqualFold(got, candidate) {
			return true
		}
	}
	return false
}
