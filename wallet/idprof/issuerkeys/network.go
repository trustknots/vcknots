package issuerkeys

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/trustknots/vcknots/wallet/common/observe"
	"github.com/trustknots/vcknots/wallet/internal/httpfetch"
)

// defaultHTTPClient is used when the Resolver carries none. It is shared, which
// is what net/http intends: a Client is safe for concurrent use and pools its
// connections.
var defaultHTTPClient = &http.Client{Timeout: httpfetch.DefaultTimeout}

func (r *Resolver) maxDocumentBytes() int64 {
	if r.MaxDocumentBytes > 0 {
		return r.MaxDocumentBytes
	}
	return httpfetch.DefaultBodyLimit
}

func (r *Resolver) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// httpClient returns the client used for metadata retrieval, with redirects
// refused: a redirect would let the host named by the issuer identifier hand
// the request to another host, whose answer would then be attributed to the
// first.
func (r *Resolver) httpClient() *http.Client {
	base := r.HTTPClient
	if base == nil {
		base = defaultHTTPClient
	}
	return httpfetch.NoRedirect(base)
}

// allowedURL parses raw and reports whether the resolver may request it.
//
// Every location the ladder reads is a well-known path derived from an issuer
// identifier, so the rules are narrow on purpose: the URL must parse with a
// host, it must be https - or http while AllowHTTP is set, which exists for a
// local test origin - and it must carry neither a query nor a fragment, since
// neither can be part of a well-known location.
func (r *Resolver) allowedURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return nil, newMechanismError(ErrIssuerURLNotAllowed, "issuer identifier is not a URL")
	}
	switch parsed.Scheme {
	case "https":
	case "http":
		if !r.AllowHTTP {
			return nil, newMechanismError(ErrIssuerURLNotAllowed, "issuer identifier is not https")
		}
	default:
		return nil, newMechanismError(ErrIssuerURLNotAllowed, "issuer identifier is not https")
	}
	if parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.RawFragment != "" {
		return nil, newMechanismError(ErrIssuerURLNotAllowed, "issuer identifier carries a query or fragment")
	}
	return parsed, nil
}

// originOf returns the scheme and authority of a URL, with a default port
// dropped, which is the form a DIF Well Known DID Configuration's `origin`
// claim is written in.
func originOf(parsed *url.URL) string {
	host := parsed.Host
	switch {
	case parsed.Scheme == "https" && strings.HasSuffix(host, ":443"):
		host = strings.TrimSuffix(host, ":443")
	case parsed.Scheme == "http" && strings.HasSuffix(host, ":80"):
		host = strings.TrimSuffix(host, ":80")
	}
	return parsed.Scheme + "://" + host
}

// fetchJSONObject retrieves a JSON object from target: a GET that asks for
// JSON within ctx, with redirects refused, a success status, a JSON media type
// (application/json, or application/jwk-set+json for a key set) and a bounded,
// non-empty body that holds a JSON object.
func (r *Resolver) fetchJSONObject(ctx context.Context, target *url.URL) (json.RawMessage, error) {
	request, err := http.NewRequestWithContext(observe.WithEndpoint(ctx, observe.EndpointIssuerKeyMaterial), http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, newMechanismError(ErrIssuerMetadataFetchFailed, "request could not be built")
	}
	request.Header.Set("Accept", "application/json")

	response, err := r.httpClient().Do(request)
	if err != nil {
		return nil, newMechanismError(ErrIssuerMetadataFetchFailed, "request failed")
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode >= http.StatusMultipleChoices && response.StatusCode < http.StatusBadRequest {
		return nil, newMechanismError(ErrIssuerMetadataFetchFailed, "redirects are not allowed")
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, newMechanismError(ErrIssuerMetadataFetchFailed, "fetch failed: HTTP "+strconv.Itoa(response.StatusCode))
	}
	if !httpfetch.MediaTypeIs(response.Header, "application/json", "application/jwk-set+json") {
		return nil, newMechanismError(ErrIssuerMetadataFetchFailed, "response is not labelled as JSON")
	}

	body, err := httpfetch.ReadLimited(response, r.maxDocumentBytes())
	if errors.Is(err, httpfetch.ErrBodyTooLarge) {
		return nil, newMechanismError(ErrIssuerMetadataFetchFailed, "response is too large")
	}
	if err != nil {
		return nil, newMechanismError(ErrIssuerMetadataFetchFailed, "body could not be read")
	}
	if len(body) == 0 {
		return nil, newMechanismError(ErrIssuerMetadataFetchFailed, "response is empty")
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(body, &probe); err != nil || probe == nil {
		return nil, newMechanismError(ErrIssuerMetadataInvalid, "response is not a JSON object")
	}
	return body, nil
}
