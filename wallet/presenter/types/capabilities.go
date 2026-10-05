package types

import (
	"context"
	"encoding/json"
)

// This file declares the capabilities a presenter plugin offers beyond the
// upstream Presenter interface. A wallet type-asserts a registered Presenter to
// the capability it needs. Every method takes a context as its first parameter
// and binds every HTTP request it makes to it.

// AdmittedRequest is a presentation request a plugin parsed and admitted under
// its trust policy. Only the plugin that admitted a request answers it; the
// response endpoint comes from the request, never from the caller.
type AdmittedRequest interface {
	Protocol() SupportedPresentationProtocol
}

// RequestObjectSource carries the Authorization Request facts a Request
// Object passed by value cannot carry itself. How the Request Object reached
// the wallet is not among them: a presenter observes delivery only when it
// fetches request_uri itself (RequestParser.ParseRequest), and a Request
// Object handed over by value is always treated as delivered by value.
type RequestObjectSource struct {
	// ClientID is the client_id of the Authorization Request that carried or
	// referenced the Request Object; the Request Object's own client_id must
	// equal it. Empty when the caller has none.
	ClientID string
}

// RequestParser parses and admits OpenID4VP 1.0 Authorization Requests.
type RequestParser interface {
	// ParseRequest parses an Authorization Request URI, dereferencing its
	// request_uri when present.
	ParseRequest(ctx context.Context, uri string) (AdmittedRequest, error)
	// ParseRequestObject authenticates a Request Object the caller already
	// holds, as a Request Object passed by value.
	ParseRequestObject(ctx context.Context, requestObject string, src RequestObjectSource) (AdmittedRequest, error)
}

// SealedAdmission is the versioned, HMAC-sealed record of an admission in
// which the presenter fetched the Request Object from request_uri itself
// (oid4vp.AdmittedRequest.Seal). It is opaque to the caller, who may store it
// with a request that spans several stateless calls and hand it back to the
// presenter that re-admits it. It carries the Request Object, so it is as
// sensitive as the Request Object is.
type SealedAdmission string

// RequestReadmitter re-admits an OpenID4VP 1.0 request from a sealed
// admission.
type RequestReadmitter interface {
	ReadmitRequest(ctx context.Context, sealed SealedAdmission, key []byte) (AdmittedRequest, error)
}

// Draft24RequestReadmitter re-admits an OpenID4VP Draft 24 request from a
// sealed admission.
type Draft24RequestReadmitter interface {
	ReadmitDraft24Request(ctx context.Context, sealed SealedAdmission, key []byte) (AdmittedRequest, error)
}

// VersionAdmitter admits, under the other OpenID4VP version, a request an
// entry point refused as written for that version (oid4vp.VersionMismatchError).
// refused is the error the refusing parse returned; only the plugin that
// produced it acts on it.
type VersionAdmitter interface {
	AdmitUnderVersion(ctx context.Context, refused error) (AdmittedRequest, error)
}

// DCAPIRequestParser parses and admits OpenID4VP 1.0 Appendix A requests
// delivered through the W3C Digital Credentials API.
type DCAPIRequestParser interface {
	ParseDCAPIRequest(ctx context.Context, invocation DCAPIInvocation) (AdmittedRequest, error)
}

// Draft24RequestParser parses and admits OpenID4VP Draft 24 Authorization
// Requests carrying a Presentation Exchange presentation_definition.
type Draft24RequestParser interface {
	ParseDraft24Request(ctx context.Context, uri string) (AdmittedRequest, error)
	ParseDraft24RequestObject(ctx context.Context, requestObject string, src RequestObjectSource) (AdmittedRequest, error)
}

// Responder answers admitted OpenID4VP 1.0 requests, by direct_post,
// direct_post.jwt or the DC API as the request asks.
type Responder interface {
	// SubmitDCQLResponse sends vp_token, keyed by DCQL credential query id.
	SubmitDCQLResponse(ctx context.Context, req AdmittedRequest, vpToken map[string][]string) (*SubmitResult, error)
	// SubmitErrorResponse sends an OpenID4VP 1.0 Section 8.5 error response.
	SubmitErrorResponse(ctx context.Context, req AdmittedRequest, code, description string) (*SubmitResult, error)
}

// PresentationExchangeResponder answers admitted Draft 24 requests with a
// Presentation Exchange response.
type PresentationExchangeResponder interface {
	SubmitPresentationExchangeResponse(ctx context.Context, req AdmittedRequest, vpToken []byte, submission PresentationSubmission) (*SubmitResult, error)
}

// SubmitResult is the outcome of answering an admitted request.
type SubmitResult struct {
	// RedirectURI is the redirect_uri the verifier returned, if any.
	RedirectURI string
	// DCAPIResponse is the object to hand back to the platform when the
	// request came through the DC API; nil otherwise.
	DCAPIResponse *DCAPIResponse
	// Encrypted reports that the response was encrypted to the verifier.
	Encrypted bool
}

// DCAPIRequest is one entry of the platform's DigitalCredentialGetRequest
// requests array. Data is the protocol data object exactly as delivered: the
// Authorization Request members for an unsigned request, {"request": <compact
// JWS>} for a signed one and {"request": {"payload":..,"signatures":[..]}} for
// a multi-signed one (OpenID4VP 1.0 Appendix A.3).
type DCAPIRequest struct {
	Protocol string          `json:"protocol"`
	Data     json.RawMessage `json:"data"`
}

// DCAPIInvocation is what the platform supplies to the wallet. The origin is
// authenticated by the platform and never taken from the request.
type DCAPIInvocation struct {
	Request DCAPIRequest
	// Origin is the calling web origin, for example "https://verifier.example".
	Origin string
}

// DCAPIResponse is the object returned to the platform (OpenID4VP 1.0 Appendix
// A.4). Protocol echoes the request protocol; Data is {"vp_token": {...}} for
// dc_api or {"response": <JWE>} for dc_api.jwt.
type DCAPIResponse struct {
	Protocol string         `json:"protocol"`
	Data     map[string]any `json:"data"`
}
