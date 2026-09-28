package oid4vp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/trustknots/vcknots/wallet/presenter/types"
)

var (
	_ types.Draft24RequestParser          = (*Oid4vpPresenter)(nil)
	_ types.PresentationExchangeResponder = (*Oid4vpPresenter)(nil)
)

// ParseDraft24Request parses and admits an OpenID4VP Draft 24 Authorization
// Request URI carrying a Presentation Exchange presentation_definition, by
// value or by reference. A request carrying dcql_query is refused with a
// *VersionMismatchError naming OpenID4VP 1.0, as the Draft 24 DCQL response
// is not implemented. The presenter's profile does not apply. The result is
// an *AdmittedRequest.
func (p *Oid4vpPresenter) ParseDraft24Request(ctx context.Context, uri string) (types.AdmittedRequest, error) {
	return asAdmitted(p.parseDraft24RequestURI(ctx, uri))
}

// ParseDraft24RequestObject is ParseRequestObject for the Draft 24 wire
// contract: the Request Object is authenticated as one passed by value.
func (p *Oid4vpPresenter) ParseDraft24RequestObject(ctx context.Context, requestObject string, src types.RequestObjectSource) (types.AdmittedRequest, error) {
	return asAdmitted(p.parseDraft24RequestObject(ctx, requestObject, src))
}

func (p *Oid4vpPresenter) parseDraft24RequestURI(ctx context.Context, uriString string) (*AdmittedRequest, error) {
	builder, err := p.newDraft24RequestBuilder(ctx)
	if err != nil {
		return nil, err
	}
	queryParams, err := authorizationRequestQuery(uriString)
	if err != nil {
		return nil, err
	}
	clientID := strings.TrimSpace(queryParams.Get("client_id"))
	if clientID != "" {
		if _, err := parseDraft24ClientID(clientID); err != nil {
			return nil, fmt.Errorf("invalid client_id in initial request: %w", err)
		}
	}
	builder.expectedClientID = clientID

	requestURI := queryParams.Get("request_uri")
	requestObj := queryParams.Get("request")
	switch {
	case requestURI != "":
		method := RequestURIMethodGET
		// Draft 24 §5.1: "Two case-sensitive valid values are defined in this
		// specification: get and post."
		switch requestURIMethod := queryParams.Get("request_uri_method"); requestURIMethod {
		case "", "get":
		case "post":
			method = RequestURIMethodPOST
		default:
			return nil, newAuthorizationRequestError(InvalidRequestURIMethodError, "request_uri_method must be 'get' or 'post' (case-sensitive), got %q", requestURIMethod)
		}
		builder.WithRequestObjectURI(requestURI, method)
	case requestObj != "":
		builder.WithRequestObject(requestObj)
	default:
		builder.WithQueryParams(queryParams)
	}
	return p.finishParse(&builder.requestCore, builder.Build, wireDraft24)
}

func (p *Oid4vpPresenter) parseDraft24RequestObject(ctx context.Context, requestObject string, src types.RequestObjectSource) (*AdmittedRequest, error) {
	builder, err := p.newDraft24RequestBuilder(ctx)
	if err != nil {
		return nil, err
	}
	clientID := strings.TrimSpace(src.ClientID)
	if clientID != "" {
		if _, err := parseDraft24ClientID(clientID); err != nil {
			return nil, fmt.Errorf("invalid client_id in initial request: %w", err)
		}
	}
	builder.applySource(clientID)
	builder.WithRequestObject(requestObject)
	return p.finishParse(&builder.requestCore, builder.Build, wireDraft24)
}

// newDraft24RequestBuilder creates the builder of one Draft 24 parse. The
// presenter's profile must be valid but does not apply.
func (p *Oid4vpPresenter) newDraft24RequestBuilder(ctx context.Context) (*draft24RequestBuilder, error) {
	if _, err := p.profileOptions(); err != nil {
		return nil, err
	}
	builder := newDraft24RequestBuilder()
	p.configureCore(ctx, &builder.requestCore)
	// Draft 24 §5.1 does not require a kid on client_metadata.jwks members.
	builder.requireClientMetadataJWKKeyIDs = false
	builder.supportedTransactionDataTypes = p.SupportedTransactionDataTypes
	builder.requestURIPost = p.requestURIPostSettings()
	return builder, nil
}

// SubmitPresentationExchangeResponse answers an admitted Draft 24 request
// with a Presentation Exchange response: vp_token and presentation_submission
// (Draft 24 §7.1). direct_post.jwt encrypts the response to the Verifier.
func (p *Oid4vpPresenter) SubmitPresentationExchangeResponse(ctx context.Context, req types.AdmittedRequest, vpToken []byte, submission types.PresentationSubmission) (*types.SubmitResult, error) {
	handle, err := p.admittedHere(req)
	if err != nil {
		return nil, err
	}
	if handle.wire != wireDraft24 {
		return nil, fmt.Errorf("%w: a Presentation Exchange response answers a Draft 24 request", ErrResponseTypeMismatch)
	}
	if len(vpToken) == 0 {
		return nil, types.ErrInvalidPresentation
	}
	redirectURI, encrypted, err := p.postPresentationExchangeResponse(ctx, handle.endpoint.String(), vpToken, submission, handle.req.State, string(handle.req.ResponseMode), handle.req.ClientMetadata)
	if err != nil {
		return nil, err
	}
	return &types.SubmitResult{RedirectURI: redirectURI, Encrypted: encrypted}, nil
}

// postPresentationExchangeResponse posts a Presentation Exchange response to
// the Response URI: in the clear under direct_post (Draft 24 §8.2), and as an
// encrypted-only JARM response under direct_post.jwt (Draft 24 §8.3.1). No
// other response mode is answered by POST.
func (p *Oid4vpPresenter) postPresentationExchangeResponse(ctx context.Context, endpoint string, vpToken []byte, submission types.PresentationSubmission, state, mode string, metadata *VerifierMetadata) (string, bool, error) {
	submissionJSON, err := json.Marshal(submission)
	if err != nil {
		return "", false, fmt.Errorf("failed to marshal presentation_submission: %w", err)
	}
	var form url.Values
	encrypted := false
	switch OAuthAuthzReqResponseMode(mode) {
	case OAuthAuthzReqResponseModeDirectPost:
		form = url.Values{"vp_token": {string(vpToken)}, "presentation_submission": {string(submissionJSON)}}
		if state != "" {
			form.Set("state", state)
		}
	case OAuthAuthzReqResponseModeDirectPostJWT:
		// Draft 24 §8.3: the JWE payload is the JSON of the response
		// parameters, presentation_submission as an object, without iss, exp
		// or aud. direct_post.jwt is never answered in plaintext.
		payload := map[string]any{
			"vp_token":                draft24VPTokenMember(vpToken),
			"presentation_submission": json.RawMessage(submissionJSON),
		}
		if state != "" {
			payload["state"] = state
		}
		payloadBytes, err := json.Marshal(payload)
		if err != nil {
			return "", false, fmt.Errorf("failed to marshal authorization response: %w", err)
		}
		token, err := encryptDraft24JARMResponse(payloadBytes, metadata)
		if err != nil {
			return "", false, fmt.Errorf("failed to create Draft24 JARM response: %w", err)
		}
		form = url.Values{"response": {token}}
		encrypted = true
	default:
		return "", false, fmt.Errorf("response_mode %q is not supported for a Presentation Exchange response", mode)
	}
	body, err := postAuthorizationResponse(ctx, p.httpClient(), endpoint, form)
	if err != nil {
		return "", encrypted, fmt.Errorf("failed to send Draft24 presentation: %w", err)
	}
	return redirectURIFromVerifierResponse(body), encrypted, nil
}

// draft24VPTokenMember is the vp_token member of a Draft 24 JARM payload.
// Draft 24 §8.1: vp_token is "a JSON String or JSON object that MUST contain a
// single Verifiable Presentation or an array of JSON Strings and JSON objects
// each of them containing a Verifiable Presentation". A compact presentation
// (a JWT VP or an SD-JWT) is a JSON string; an array of presentations or an
// ldp_vp object is embedded as JSON, never as the string of its encoding.
func draft24VPTokenMember(vpToken []byte) any {
	trimmed := bytes.TrimSpace(vpToken)
	if len(trimmed) > 0 && (trimmed[0] == '[' || trimmed[0] == '{') && json.Valid(trimmed) {
		return json.RawMessage(trimmed)
	}
	return string(vpToken)
}
