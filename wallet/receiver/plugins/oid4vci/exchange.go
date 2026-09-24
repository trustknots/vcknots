package oid4vci

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/trustknots/vcknots/wallet/internal/httpfetch"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

// exchange is one OpenID4VCI HTTP request. The body, the extra headers and the
// DPoP proof are produced per attempt, so a resent request never replays a
// signed or single-use value (RFC 9449 Section 4.2 jti, RFC 7523 Section 3 jti).
type exchange struct {
	method string
	url    url.URL
	// contentType is the request Content-Type; empty sends none.
	contentType string
	// accept is the Accept header; empty means application/json.
	accept string
	// body builds the request body; nil sends none.
	body func() ([]byte, error)
	// header adds request headers, such as the client attestation; nil adds none.
	header func(http.Header) error
	// accessToken, when set, is sent in the Authorization header with the
	// scheme its token_type names.
	accessToken *types.CredentialIssuanceAccessToken
	// dpop builds the DPoP proof for the nonce the receiver holds for the
	// server. nil, or an empty proof, sends no DPoP header.
	dpop types.DPoPProofFactory
	// limit bounds the response body; zero means httpfetch.DefaultBodyLimit.
	limit int64
}

// exchangeResponse is a response whose body has been read within the limit.
type exchangeResponse struct {
	statusCode int
	header     http.Header
	body       []byte
}

func (r *exchangeResponse) ok() bool {
	return r.statusCode >= 200 && r.statusCode < 300
}

// statusError reports a non-2xx response by its status and OAuth error code.
func (r *exchangeResponse) statusError() *httpStatusError {
	return &httpStatusError{statusCode: r.statusCode, oauthError: sanitizeErrorText(oauthErrorCode(r.body), maxErrorCodeLength)}
}

// do performs ex and returns the response of the last attempt, whatever its
// status; only transport failures, refused redirects and oversized bodies are
// errors. Every DPoP-Nonce a response carries is remembered for the server.
//
// A request is resent at most once, and only when all of these hold:
//   - the attempt carried a DPoP proof built by ex.dpop;
//   - the server answered use_dpop_nonce: the `error` member of an RFC 9449
//     Section 8 authorization server response, or the error parameter of a
//     Section 9 `WWW-Authenticate: DPoP` challenge;
//   - it supplied a DPoP-Nonce other than the one the proof carried.
//
// No other refusal is resent: invalid_grant, invalid_proof, invalid_nonce
// (whose c_nonce refresh is RequestCredential's job),
// issuance_pending and the rest reach the caller from the first response.
func (o *Oid4vciReceiver) do(ctx context.Context, ex exchange) (*exchangeResponse, error) {
	if err := o.requireEndpointScheme(ex.url); err != nil {
		return nil, err
	}
	dpopNonce := o.dpopNonceFor(ex.url)
	for attempt := 0; ; attempt++ {
		proofSent, response, err := o.send(ctx, ex, dpopNonce)
		if err != nil {
			return nil, err
		}
		if response.ok() || attempt > 0 || !proofSent || !isUseDPoPNonce(response) {
			return response, nil
		}
		fresh := strings.TrimSpace(response.header.Get("DPoP-Nonce"))
		if fresh == "" || fresh == dpopNonce {
			return response, nil
		}
		dpopNonce = fresh
	}
}

// send performs one attempt of ex with a proof built for dpopNonce.
func (o *Oid4vciReceiver) send(ctx context.Context, ex exchange, dpopNonce string) (bool, *exchangeResponse, error) {
	var body io.Reader
	if ex.body != nil {
		built, err := ex.body()
		if err != nil {
			return false, nil, err
		}
		body = bytes.NewReader(built)
	}
	request, err := http.NewRequestWithContext(ctx, ex.method, ex.url.String(), body)
	if err != nil {
		return false, nil, err
	}
	accept := ex.accept
	if accept == "" {
		accept = "application/json"
	}
	request.Header.Set("Accept", accept)
	if ex.contentType != "" {
		request.Header.Set("Content-Type", ex.contentType)
	}
	if ex.header != nil {
		if err := ex.header(request.Header); err != nil {
			return false, nil, err
		}
	}
	if ex.accessToken != nil {
		request.Header.Set("Authorization", authorizationScheme(ex.accessToken.TokenType)+" "+ex.accessToken.Token)
	}
	proofSent := false
	if ex.dpop != nil {
		proof, err := ex.dpop(dpopNonce)
		if err != nil {
			return false, nil, err
		}
		if proof != "" {
			request.Header.Set("DPoP", proof)
			proofSent = true
		}
	}

	response, err := httpfetch.NoRedirect(o.HTTPClient).Do(request)
	if err != nil {
		return false, nil, err
	}
	defer response.Body.Close()
	o.rememberDPoPNonce(ex.url, response.Header.Get("DPoP-Nonce"))
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		return false, nil, fmt.Errorf("OID4VCI endpoint answered HTTP %d: %w", response.StatusCode, ErrHTTPRedirectNotAllowed)
	}
	limit := ex.limit
	if limit == 0 {
		limit = httpfetch.DefaultBodyLimit
	}
	responseBody, err := httpfetch.ReadLimited(response, limit)
	if err != nil {
		return false, nil, err
	}
	return proofSent, &exchangeResponse{statusCode: response.StatusCode, header: response.Header, body: responseBody}, nil
}

// requireEndpointScheme refuses a non-https endpoint unless AllowHTTP is set.
func (o *Oid4vciReceiver) requireEndpointScheme(endpointURL url.URL) error {
	if !o.AllowHTTP && !strings.EqualFold(endpointURL.Scheme, "https") {
		return fmt.Errorf("unsupported URL scheme for OID4VCI endpoint: %q (https required)", endpointURL.Scheme)
	}
	return nil
}

// isUseDPoPNonce reports whether a response is the RFC 9449 use_dpop_nonce
// challenge: the `error` member of an authorization server error response
// (Section 8) or the error parameter of a resource server's DPoP challenge
// (Section 9).
func isUseDPoPNonce(response *exchangeResponse) bool {
	const code = "use_dpop_nonce"
	return oauthErrorCode(response.body) == code || dpopChallengeError(response.header) == code
}

// dpopChallengeError returns the error parameter of the DPoP challenge in the
// WWW-Authenticate header (RFC 9449 Section 7.1), or "" when there is none.
func dpopChallengeError(header http.Header) string {
	for _, value := range header.Values("WWW-Authenticate") {
		scheme := ""
		for _, item := range splitChallengeItems(value) {
			name, rest, hasSpace := strings.Cut(item, " ")
			if !strings.Contains(name, "=") {
				scheme = name
				if !hasSpace {
					continue
				}
				item = strings.TrimSpace(rest)
			}
			if !strings.EqualFold(scheme, dpopAuthorizationScheme) {
				continue
			}
			key, param, found := strings.Cut(item, "=")
			if found && strings.EqualFold(strings.TrimSpace(key), "error") {
				return strings.Trim(strings.TrimSpace(param), `"`)
			}
		}
	}
	return ""
}

// dpopChallenged reports whether the WWW-Authenticate header carries a DPoP
// challenge.
func dpopChallenged(header http.Header) bool {
	for _, value := range header.Values("WWW-Authenticate") {
		for _, item := range splitChallengeItems(value) {
			name, _, _ := strings.Cut(item, " ")
			if !strings.Contains(name, "=") && strings.EqualFold(name, dpopAuthorizationScheme) {
				return true
			}
		}
	}
	return false
}

// splitChallengeItems splits a WWW-Authenticate value (RFC 9110 Section 11.6.1)
// at the commas outside quoted strings. Each item is either a scheme, a scheme
// followed by its first parameter, or a further parameter.
func splitChallengeItems(value string) []string {
	var items []string
	var current strings.Builder
	quoted, escaped := false, false
	for _, r := range value {
		switch {
		case escaped:
			escaped = false
		case quoted && r == '\\':
			escaped = true
		case r == '"':
			quoted = !quoted
		case r == ',' && !quoted:
			if item := strings.TrimSpace(current.String()); item != "" {
				items = append(items, item)
			}
			current.Reset()
			continue
		}
		current.WriteRune(r)
	}
	if item := strings.TrimSpace(current.String()); item != "" {
		items = append(items, item)
	}
	return items
}

// bearerTokenChallenged reports whether a response to a request sent with a
// Bearer access token asks for DPoP: a use_dpop_nonce challenge or a DPoP
// WWW-Authenticate challenge. The wallet holds no proof key for such a token,
// so the request cannot be corrected and is reported as ErrDPoPRequired.
func bearerTokenChallenged(accessToken *types.CredentialIssuanceAccessToken, response *exchangeResponse) bool {
	if accessToken == nil || authorizationScheme(accessToken.TokenType) == dpopAuthorizationScheme {
		return false
	}
	return isUseDPoPNonce(response) || dpopChallenged(response.header)
}

// doJSON performs ex and decodes a 2xx JSON body into target. A non-2xx
// response is returned as *httpStatusError; an empty body or a nil target
// decodes nothing.
func (o *Oid4vciReceiver) doJSON(ctx context.Context, ex exchange, target any) error {
	response, err := o.do(ctx, ex)
	if err != nil {
		return err
	}
	if !response.ok() {
		return response.statusError()
	}
	if target == nil || len(response.body) == 0 {
		return nil
	}
	if err := json.Unmarshal(response.body, target); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}
	return nil
}
