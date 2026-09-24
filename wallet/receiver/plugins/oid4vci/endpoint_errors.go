package oid4vci

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Stage names the endpoint an OpenID4VCI 1.0 issuance was talking to when it
// failed. It exists so a caller can report which step of the flow the issuer or
// the authorization server refused — the wallet's own report to the holder, and
// often the only actionable part of a failure — without parsing error text or
// keeping its own record of the requests the library performed.
type Stage string

const (
	// StageIssuerMetadata is the Section 12.2.2 Credential Issuer Metadata
	// document.
	StageIssuerMetadata Stage = "issuer_metadata"
	// StageAuthorizationServerMetadata is the RFC 8414 authorization server
	// metadata document of the Section 12.3 selected authorization server.
	StageAuthorizationServerMetadata Stage = "authorization_server_metadata"
	// StagePAR is the RFC 9126 Pushed Authorization Request endpoint.
	StagePAR Stage = "pushed_authorization_request"
	// StageToken is the Section 6.1 Token Endpoint, for both the authorization
	// code and the pre-authorized code grant.
	StageToken Stage = "token"
	// StageNonce is the Section 7 Nonce Endpoint.
	StageNonce Stage = "nonce"
)

// EndpointError reports that one endpoint of an issuance did not answer with
// the document the flow needs: it refused the request with an HTTP status, or
// the request never produced a usable response at all.
//
// The Section 8 Credential Endpoint and the Section 9 Deferred Credential
// Endpoint are not reported through this type. Their refusals carry the
// Section 8.3.1.2 error code the wallet acts on — a fresh c_nonce, a retry, a
// terminal failure — so they arrive as *types.CredentialEndpointError instead.
//
// The response body is not kept, neither in the fields nor in the message: it
// is attacker-influenced text. Err keeps the underlying cause, so errors.Is
// still finds the sentinels of this package (for example
// ErrHTTPRedirectNotAllowed or ErrIssuerIdentifierMismatch) and the transport
// errors underneath them.
type EndpointError struct {
	// Stage is the endpoint that failed.
	Stage Stage
	// StatusCode is the HTTP status the endpoint answered with, or 0 when the
	// failure happened before a response was read — a transport error, a
	// refused redirect, or a body that did not decode.
	StatusCode int
	// OAuthError is the RFC 6749 Section 5.2 `error` member of the response
	// body, when the endpoint returned one. Empty otherwise.
	OAuthError string
	// Err is the underlying cause.
	Err error
}

// Error implements error.
func (e *EndpointError) Error() string {
	if e == nil {
		return "OpenID4VCI endpoint error"
	}
	prefix := fmt.Sprintf("%s endpoint failed", e.Stage)
	switch {
	case e.StatusCode != 0 && e.OAuthError != "":
		prefix = fmt.Sprintf("%s endpoint returned HTTP %d %s", e.Stage, e.StatusCode, e.OAuthError)
	case e.StatusCode != 0:
		prefix = fmt.Sprintf("%s endpoint returned HTTP %d", e.Stage, e.StatusCode)
	}
	if e.Err == nil {
		return prefix
	}
	return prefix + ": " + e.Err.Error()
}

// ErrorCode names the endpoint that did not answer with the document the flow
// needs. The stage is the classification: a caller reports which step of the
// issuance the Credential Issuer or the authorization server refused without
// keeping its own record of the requests this package performed.
func (e *EndpointError) ErrorCode() string {
	if e == nil {
		return "oid4vci_endpoint_failed"
	}
	switch e.Stage {
	case StageIssuerMetadata:
		return "issuer_metadata_fetch_failed"
	case StageAuthorizationServerMetadata:
		return "authorization_server_metadata_fetch_failed"
	case StagePAR:
		return "pushed_authorization_request_failed"
	case StageToken:
		return "token_endpoint_rejected"
	case StageNonce:
		return "nonce_request_failed"
	default:
		return "oid4vci_endpoint_failed"
	}
}

// Unwrap returns the wrapped error.
func (e *EndpointError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// stageError tags err with the endpoint it came from. An error that already
// names a stage is returned unchanged, so the outermost public method does not
// relabel a failure a nested one already classified.
func stageError(stage Stage, err error) error {
	if err == nil {
		return nil
	}
	var already *EndpointError
	if errors.As(err, &already) {
		return err
	}
	endpointError := &EndpointError{Stage: stage, Err: err}
	var statusError *httpStatusError
	if errors.As(err, &statusError) {
		endpointError.StatusCode = statusError.statusCode
		endpointError.OAuthError = statusError.oauthError
	}
	return endpointError
}

// httpStatusError is the unexpected HTTP status of a request this package made,
// with the RFC 6749 Section 5.2 `error` code of the body when it had one.
type httpStatusError struct {
	statusCode int
	oauthError string
}

func (e *httpStatusError) Error() string {
	if e.oauthError != "" {
		return fmt.Sprintf("unexpected status code: %d, error: %s", e.statusCode, e.oauthError)
	}
	return fmt.Sprintf("unexpected status code: %d", e.statusCode)
}

const (
	// maxErrorCodeLength bounds an `error` code taken from a response.
	maxErrorCodeLength = 64
	// maxErrorDescriptionLength bounds an `error_description` taken from a
	// response.
	maxErrorDescriptionLength = 256
)

// sanitizeErrorText reduces text from a response to the characters RFC 6749
// Section 5.2 allows in `error` and `error_description` (printable ASCII
// without `"` and `\`), replacing any other with "?", and truncates it to max
// bytes. The result is safe to log and render.
func sanitizeErrorText(text string, max int) string {
	var sanitized strings.Builder
	for _, r := range text {
		if sanitized.Len() >= max {
			break
		}
		if r < 0x20 || r > 0x7e || r == '"' || r == '\\' {
			r = '?'
		}
		sanitized.WriteRune(r)
	}
	return sanitized.String()
}

// isNotFound reports the status after which FetchIssuerMetadata may try the
// Draft 13 metadata location.
func (e *httpStatusError) isNotFound() bool {
	return e != nil && e.statusCode == http.StatusNotFound
}
