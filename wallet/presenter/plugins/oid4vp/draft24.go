package oid4vp

import (
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
// Request URI carrying a Presentation Exchange presentation_definition or a
// Draft 24 dcql_query. The presenter's profile does not apply. The result is
// an *AdmittedRequest.
func (p *Oid4vpPresenter) ParseDraft24Request(ctx context.Context, uri string) (types.AdmittedRequest, error) {
	return asAdmitted(p.parseDraft24RequestURI(ctx, uri))
}

// ParseDraft24RequestObject is ParseRequestObject for the Draft 24 wire
// contract.
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
		switch requestURIMethod := queryParams.Get("request_uri_method"); strings.ToLower(requestURIMethod) {
		case "", "get":
		case "post":
			method = RequestURIMethodPOST
		default:
			return nil, fmt.Errorf("unsupported request_uri_method: %s", requestURIMethod)
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
	builder.applySource(clientID, src)
	builder.WithRequestObject(requestObject)
	return p.finishParse(&builder.requestCore, builder.Build, wireDraft24)
}

// newDraft24RequestBuilder creates the builder of one Draft 24 parse. The
// presenter's profile must be valid but does not apply.
func (p *Oid4vpPresenter) newDraft24RequestBuilder(ctx context.Context) (*draft24RequestBuilder, error) {
	if _, err := p.normalizedProfile(); err != nil {
		return nil, err
	}
	builder := newDraft24RequestBuilder()
	p.configureCore(ctx, &builder.requestCore)
	builder.supportedTransactionDataTypes = p.SupportedTransactionDataTypes
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

// postPresentationExchangeResponse posts a Presentation Exchange response.
// mode is the request's response_mode; "" with an
// authorization_encrypted_response_alg in metadata sends the JARM shape.
func (p *Oid4vpPresenter) postPresentationExchangeResponse(ctx context.Context, endpoint string, vpToken []byte, submission types.PresentationSubmission, state, mode string, metadata *VerifierMetadata) (string, bool, error) {
	submissionJSON, err := json.Marshal(submission)
	if err != nil {
		return "", false, fmt.Errorf("failed to marshal presentation_submission: %w", err)
	}
	form := url.Values{"vp_token": {string(vpToken)}, "presentation_submission": {string(submissionJSON)}}
	if state != "" {
		form.Set("state", state)
	}
	encrypted := false
	switch {
	case mode == string(OAuthAuthzReqResponseModeDirectPostJWT):
		// OID4VP 1.0 Section 8.3: the JWE payload carries the response
		// parameters as top-level JSON members, so presentation_submission
		// is the object itself. direct_post.jwt is never answered in
		// plaintext.
		payload := map[string]any{
			"vp_token":                string(vpToken),
			"presentation_submission": json.RawMessage(submissionJSON),
		}
		if state != "" {
			payload["state"] = state
		}
		payloadBytes, err := json.Marshal(payload)
		if err != nil {
			return "", false, fmt.Errorf("failed to marshal authorization response: %w", err)
		}
		token, err := p.encryptAuthorizationResponseJWE(payloadBytes, metadata)
		if err != nil {
			return "", false, fmt.Errorf("failed to create Draft24 encrypted authorization response: %w", err)
		}
		form = url.Values{"response": {token}}
		encrypted = true
	case mode == "" && metadata != nil && metadata.AuthorizationEncryptedResponseAlg != "":
		// A caller that names no response mode and asks for encryption
		// through authorization_encrypted_response_alg gets the JARM shape,
		// with presentation_submission as a JSON string.
		payload := map[string]any{"vp_token": string(vpToken), "presentation_submission": string(submissionJSON)}
		if state != "" {
			payload["state"] = state
		}
		token, err := p.encryptJARMPayload(payload, metadata.AuthorizationEncryptedResponseAlg, metadata.AuthorizationEncryptedResponseEnc, &metadata.Jwks)
		if err != nil {
			return "", false, fmt.Errorf("failed to create Draft24 JARM response: %w", err)
		}
		form = url.Values{"response": {token}}
		encrypted = true
	}
	body, err := postAuthorizationResponse(ctx, p.httpClient(), endpoint, form)
	if err != nil {
		return "", encrypted, fmt.Errorf("failed to send Draft24 presentation: %w", err)
	}
	return redirectURIFromVerifierResponse(body), encrypted, nil
}
