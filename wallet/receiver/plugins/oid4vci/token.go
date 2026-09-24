package oid4vci

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"strings"

	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/common/observe"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

// FetchAccessToken performs the pre-authorized code token request. It is a
// types.Receiver method and carries no context; it binds its request to
// context.Background().
func (o *Oid4vciReceiver) FetchAccessToken(
	receivingTypes types.SupportedReceivingTypes,
	endpoint common.URIField,
	authzCode string,
	txCode string,
	opts ...types.TokenRequestOption,
) (*types.CredentialIssuanceAccessToken, error) {
	ctx := observe.WithEndpoint(context.Background(), observe.EndpointToken)
	if receivingTypes != types.Oid4vci {
		return nil, fmt.Errorf("unsupported flavor: %v", receivingTypes)
	}
	normalized, err := o.normalizedProfile()
	if err != nil {
		return nil, err
	}
	formData := url.Values{}
	formData.Set("grant_type", string(types.PreAuthorizedCode))
	formData.Set("pre-authorized_code", authzCode)
	if txCode != "" {
		formData.Set("tx_code", txCode)
	}
	requestConfig := types.NewTokenRequestConfig(opts...)
	if requestConfig.ClientAssertion != "" {
		// private_key_jwt identifies the client by client_id, and an empty one
		// would only be rejected at the authorization server, where the cause
		// is far harder to see.
		if strings.TrimSpace(requestConfig.ClientID) == "" {
			return nil, fmt.Errorf("client_id is required when a client assertion is sent")
		}
		formData.Set("client_assertion", requestConfig.ClientAssertion)
		formData.Set("client_assertion_type", types.ClientAssertionTypeJWTBearer)
	}
	// Sent for both authenticated and unauthenticated requests: client_id is
	// OPTIONAL for the pre-authorized code grant, so it is included whenever the
	// caller configured one.
	if strings.TrimSpace(requestConfig.ClientID) != "" {
		formData.Set("client_id", requestConfig.ClientID)
	}
	endpointURL := url.URL(endpoint)
	if requestConfig.ClientAssertion != "" {
		if err := requireSecureClientAssertionTransport(endpointURL); err != nil {
			return nil, err
		}
	}

	body := []byte(formData.Encode())
	response, err := o.do(ctx, exchange{
		method:      http.MethodPost,
		url:         endpointURL,
		contentType: "application/x-www-form-urlencoded",
		body:        func() ([]byte, error) { return body, nil },
		header: func(header http.Header) error {
			if requestConfig.DPoPProof != "" {
				header.Set("DPoP", requestConfig.DPoPProof)
			}
			return nil
		},
	})
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	if response.statusCode != http.StatusOK {
		if isUseDPoPNonce(response) {
			return nil, types.NewDPoPNonceError(response.header.Get("DPoP-Nonce"), types.ErrTokenRequestFailed)
		}
		statusError := response.statusError()
		if response.statusCode == http.StatusBadRequest && statusError.oauthError != "" {
			return nil, fmt.Errorf("token request failed: %w: %w", statusError, types.ErrTokenRequestFailed)
		}
		return nil, statusError
	}

	var accessToken types.CredentialIssuanceAccessToken
	if err := json.Unmarshal(response.body, &accessToken); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}
	if err := requireDPoPTokenType(normalized, accessToken.TokenType); err != nil {
		return nil, err
	}
	return &accessToken, nil
}

// PushAuthorizationRequest sends an RFC 9126 Pushed Authorization Request
// (OpenID4VCI 1.0 Section 5.1.4). RFC 9126 Section 2 has it carry the client
// authentication of the token endpoint.
func (o *Oid4vciReceiver) PushAuthorizationRequest(ctx context.Context, endpoint common.URIField, request types.PushedAuthorizationRequest, auth types.ClientAuthentication) (*types.PushedAuthorizationResponse, error) {
	if _, err := o.normalizedProfile(); err != nil {
		return nil, err
	}
	formData := url.Values{}
	formData.Set("response_type", request.ResponseType)
	formData.Set("client_id", request.ClientID)
	formData.Set("redirect_uri", request.RedirectURI)
	// Section 5.1.1/5.1.2: scope and authorization_details are alternative
	// ways to select the Credential Configuration; empty values are omitted.
	if request.Scope != "" {
		formData.Set("scope", request.Scope)
	}
	if len(request.AuthorizationDetails) > 0 {
		encoded, err := json.Marshal(request.AuthorizationDetails)
		if err != nil {
			return nil, fmt.Errorf("failed to encode authorization_details: %w", err)
		}
		formData.Set("authorization_details", string(encoded))
	}
	formData.Set("state", request.State)
	formData.Set("code_challenge", request.CodeChallenge)
	formData.Set("code_challenge_method", request.CodeChallengeMethod)
	if request.IssuerState != "" {
		formData.Set("issuer_state", request.IssuerState)
	}
	endpointURL := url.URL(endpoint)
	if err := requireClientAssertionPrerequisites(endpointURL, request.ClientID, auth); err != nil {
		return nil, err
	}

	var response types.PushedAuthorizationResponse
	if err := o.postForm(observe.WithEndpoint(ctx, observe.EndpointPushedAuthorization), endpointURL, formData, auth, &response); err != nil {
		return nil, stageError(StagePAR, fmt.Errorf("failed to push authorization request: %w", err))
	}
	return &response, nil
}

// RequestToken sends an OpenID4VCI 1.0 Section 6.1 Token Request. Under HAIP
// a token_type other than DPoP is refused with ErrDPoPRequired.
func (o *Oid4vciReceiver) RequestToken(ctx context.Context, endpoint common.URIField, request types.TokenRequest, auth types.ClientAuthentication) (*types.CredentialIssuanceAccessToken, error) {
	normalized, err := o.normalizedProfile()
	if err != nil {
		return nil, err
	}
	formData, err := tokenRequestForm(request)
	if err != nil {
		return nil, err
	}
	endpointURL := url.URL(endpoint)
	if err := requireClientAssertionPrerequisites(endpointURL, request.ClientID, auth); err != nil {
		return nil, err
	}
	var response types.CredentialIssuanceAccessToken
	if err := o.postForm(observe.WithEndpoint(ctx, observe.EndpointToken), endpointURL, formData, auth, &response); err != nil {
		return nil, stageError(StageToken, fmt.Errorf("token request failed: %w", err))
	}
	if err := requireDPoPTokenType(normalized, response.TokenType); err != nil {
		return nil, err
	}
	return &response, nil
}

// tokenRequestForm encodes request as the Section 6.1 form body.
func tokenRequestForm(request types.TokenRequest) (url.Values, error) {
	formData := url.Values{}
	switch request.GrantType {
	case types.AuthorizationCode:
		if strings.TrimSpace(request.Code) == "" {
			return nil, fmt.Errorf("%w: code is required", common.ErrInvalidInput)
		}
		formData.Set("grant_type", string(types.AuthorizationCode))
		formData.Set("code", request.Code)
		setIfNotEmpty(formData, "redirect_uri", request.RedirectURI)
		setIfNotEmpty(formData, "code_verifier", request.CodeVerifier)
	case types.PreAuthorizedCode:
		if strings.TrimSpace(request.PreAuthorizedCode) == "" {
			return nil, fmt.Errorf("%w: pre-authorized_code is required", common.ErrInvalidInput)
		}
		formData.Set("grant_type", string(types.PreAuthorizedCode))
		formData.Set("pre-authorized_code", request.PreAuthorizedCode)
		// Section 6.1: tx_code is sent when the Credential Offer asked for one.
		setIfNotEmpty(formData, "tx_code", request.TxCode)
	default:
		return nil, fmt.Errorf("%w: unsupported grant_type %q", common.ErrInvalidInput, request.GrantType)
	}
	setIfNotEmpty(formData, "client_id", strings.TrimSpace(request.ClientID))
	if len(request.AuthorizationDetails) > 0 {
		encoded, err := json.Marshal(request.AuthorizationDetails)
		if err != nil {
			return nil, fmt.Errorf("failed to encode authorization_details: %w", err)
		}
		formData.Set("authorization_details", string(encoded))
	}
	return formData, nil
}

func setIfNotEmpty(formData url.Values, name, value string) {
	if value != "" {
		formData.Set(name, value)
	}
}

// requireClientAssertionPrerequisites checks, before any request, that a
// private_key_jwt client assertion names its client and travels protected.
func requireClientAssertionPrerequisites(endpointURL url.URL, clientID string, auth types.ClientAuthentication) error {
	if auth.ClientAssertion == nil {
		return nil
	}
	if strings.TrimSpace(clientID) == "" {
		return fmt.Errorf("%w: client_id is required when a client assertion is sent", common.ErrInvalidInput)
	}
	return requireSecureClientAssertionTransport(endpointURL)
}

// FetchClientAttestationChallenge fetches a challenge from the authorization
// server's challenge endpoint. ctx bounds the request.
func (o *Oid4vciReceiver) FetchClientAttestationChallenge(ctx context.Context, endpoint common.URIField) (*types.ClientAttestationChallengeResponse, error) {
	var response types.ClientAttestationChallengeResponse
	if err := o.doJSON(observe.WithEndpoint(ctx, observe.EndpointAttestationChallenge), exchange{method: http.MethodPost, url: url.URL(endpoint)}, &response); err != nil {
		return nil, fmt.Errorf("failed to fetch client attestation challenge: %w", err)
	}
	return &response, nil
}

// postForm posts formData to an authorization server endpoint and decodes a
// 2xx JSON response into target. The client assertion, the attestation headers
// and the DPoP proof of auth are built again for every attempt.
func (o *Oid4vciReceiver) postForm(ctx context.Context, endpoint url.URL, formData url.Values, auth types.ClientAuthentication, target any) error {
	return o.doJSON(ctx, exchange{
		method:      http.MethodPost,
		url:         endpoint,
		contentType: "application/x-www-form-urlencoded",
		body: func() ([]byte, error) {
			if auth.ClientAssertion == nil {
				return []byte(formData.Encode()), nil
			}
			assertion, err := auth.ClientAssertion()
			if err != nil {
				return nil, fmt.Errorf("failed to generate client assertion: %w", err)
			}
			attempt := maps.Clone(formData)
			setClientAssertionForm(attempt, assertion)
			return []byte(attempt.Encode()), nil
		},
		header: func(header http.Header) error {
			if auth.ClientAttestation == nil {
				return nil
			}
			headers, err := auth.ClientAttestation()
			if err != nil {
				return err
			}
			setAttestationHeaders(header, headers)
			return nil
		},
		dpop: auth.DPoP,
	}, target)
}

// requireSecureClientAssertionTransport refuses to send a client assertion
// over plain HTTP to a host other than loopback (RFC 6749 Section 10.8).
func requireSecureClientAssertionTransport(endpointURL url.URL) error {
	if strings.EqualFold(endpointURL.Scheme, "https") || common.IsLoopbackHost(endpointURL.Hostname()) {
		return nil
	}
	return fmt.Errorf(
		"refusing to send a client assertion to %q over %q: https is required for any host other than loopback",
		endpointURL.Host, endpointURL.Scheme)
}

// setClientAssertionForm adds the RFC 7523 Section 2.2 private_key_jwt
// parameters; an empty assertion adds none.
func setClientAssertionForm(formData url.Values, clientAssertion string) {
	if strings.TrimSpace(clientAssertion) == "" {
		return
	}
	formData.Set("client_assertion", clientAssertion)
	formData.Set("client_assertion_type", types.ClientAssertionTypeJWTBearer)
}

// setAttestationHeaders adds the OAuth-Client-Attestation headers of
// draft-ietf-oauth-attestation-based-client-auth Section 6.1; empty values are
// omitted.
func setAttestationHeaders(header http.Header, headers types.OAuthClientAttestationHeaders) {
	if headers.ClientAttestation != "" {
		header.Set("OAuth-Client-Attestation", headers.ClientAttestation)
	}
	if headers.ClientAttestationPop != "" {
		header.Set("OAuth-Client-Attestation-PoP", headers.ClientAttestationPop)
	}
}

// oauthErrorCode returns the RFC 6749 Section 5.2 `error` member of a JSON
// error response, or "" when the body is not one.
func oauthErrorCode(bodyBytes []byte) string {
	var errorResponse struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(bodyBytes, &errorResponse); err != nil {
		return ""
	}
	return strings.TrimSpace(errorResponse.Error)
}
