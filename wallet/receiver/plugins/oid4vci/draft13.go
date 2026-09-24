package oid4vci

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/common/observe"
	"github.com/trustknots/vcknots/wallet/internal/httpfetch"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

// This file carries the OpenID4VCI Draft 13 wire shapes that differ from
// OpenID4VCI 1.0. Two of them matter:
//
//   - the Credential Request names the credential with `format` plus a
//     format-specific member, or with `credential_identifier`, and carries a
//     single `proof` object (Draft 13 Section 7.2). Final 1.0 replaced that with
//     `credential_configuration_id` and a `proofs` array (Section 8.1).
//   - the Credential Error Response may carry a fresh `c_nonce` (Draft 13
//     Section 7.3.2), which is how a wallet recovers from `invalid_proof`.
//     Final 1.0 moved that to the Nonce Endpoint and the error no longer
//     carries one.
//
// Everything else — the deferred credential request of Section 9 and the
// notification of Section 10 — has the same body in both versions, so the
// difference is only which error shape comes back.

// RequestDraft13Credential posts a Draft 13 Section 7.2 Credential Request. A
// refusal is a *Draft13CredentialEndpointError, which carries the fresh
// c_nonce of a Section 7.3.2 invalid_proof response.
func (o *Oid4vciReceiver) RequestDraft13Credential(
	ctx context.Context,
	endpoint common.URIField,
	accessToken types.CredentialIssuanceAccessToken,
	request types.Draft13CredentialRequest,
	proofFactory types.DPoPProofFactory,
) (*types.Draft13CredentialResponse, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to encode draft13 credential request: %w", err)
	}
	return o.postDraft13CredentialEndpoint(observe.WithEndpoint(ctx, observe.EndpointCredential), endpoint, accessToken, body, proofFactory)
}

// RequestDraft13DeferredCredential posts a Draft 13 Section 9 Deferred
// Credential Request for transactionID.
func (o *Oid4vciReceiver) RequestDraft13DeferredCredential(
	ctx context.Context,
	endpoint common.URIField,
	accessToken types.CredentialIssuanceAccessToken,
	transactionID string,
	proofFactory types.DPoPProofFactory,
) (*types.Draft13CredentialResponse, error) {
	if strings.TrimSpace(transactionID) == "" {
		return nil, fmt.Errorf("transaction_id is required for a deferred credential request")
	}
	body, err := json.Marshal(map[string]string{"transaction_id": transactionID})
	if err != nil {
		return nil, fmt.Errorf("failed to encode draft13 deferred credential request: %w", err)
	}
	return o.postDraft13CredentialEndpoint(observe.WithEndpoint(ctx, observe.EndpointDeferredCredential), endpoint, accessToken, body, proofFactory)
}

// SendDraft13Notification posts a Draft 13 Section 10.1 Notification Request.
func (o *Oid4vciReceiver) SendDraft13Notification(
	ctx context.Context,
	endpoint common.URIField,
	accessToken types.CredentialIssuanceAccessToken,
	notification types.NotificationRequest,
	proofFactory types.DPoPProofFactory,
) error {
	if strings.TrimSpace(notification.NotificationID) == "" {
		return fmt.Errorf("notification_id is required for a notification request")
	}
	body, err := json.Marshal(notification)
	if err != nil {
		return fmt.Errorf("failed to encode draft13 notification request: %w", err)
	}
	_, _, err = o.doDraft13ProtectedPost(observe.WithEndpoint(ctx, observe.EndpointNotification), endpoint, accessToken, body, proofFactory)
	return err
}

func (o *Oid4vciReceiver) postDraft13CredentialEndpoint(
	ctx context.Context,
	endpoint common.URIField,
	accessToken types.CredentialIssuanceAccessToken,
	body []byte,
	proofFactory types.DPoPProofFactory,
) (*types.Draft13CredentialResponse, error) {
	responseBody, _, err := o.doDraft13ProtectedPost(ctx, endpoint, accessToken, body, proofFactory)
	if err != nil {
		return nil, err
	}
	return decodeDraft13CredentialResponse(responseBody)
}

// doDraft13ProtectedPost posts body to a token-protected Draft 13 endpoint
// through the shared request primitive and reports a refusal in the Draft 13
// error shape. An invalid_proof refusal is returned to the caller, which owns
// the Section 7.3.2 retry with the fresh c_nonce.
func (o *Oid4vciReceiver) doDraft13ProtectedPost(
	ctx context.Context,
	endpoint common.URIField,
	accessToken types.CredentialIssuanceAccessToken,
	body []byte,
	proofFactory types.DPoPProofFactory,
) ([]byte, string, error) {
	response, err := o.postWithAccessToken(ctx, endpoint, accessToken, body, "application/json", proofFactory, httpfetch.CredentialBodyLimit)
	if err != nil {
		return nil, "", err
	}
	if response.ok() {
		return response.body, response.header.Get("Content-Type"), nil
	}
	if bearerTokenChallenged(&accessToken, response) {
		return nil, "", ErrDPoPRequired
	}
	return nil, "", newDraft13CredentialEndpointError(response.statusCode, response.header.Get("Content-Type"), response.body, response.header.Get("DPoP-Nonce"))
}

// newDraft13CredentialEndpointError reads a non-2xx Draft 13 endpoint response.
// A JSON body is parsed for the Section 7.3.1 members; any other content type
// leaves Code empty and only the status is reported, because an unparsed body
// is attacker-influenced text this library does not carry further.
func newDraft13CredentialEndpointError(statusCode int, contentType string, body []byte, dpopNonce string) *types.Draft13CredentialEndpointError {
	endpointError := &types.Draft13CredentialEndpointError{
		StatusCode: statusCode,
		DPoPNonce:  strings.TrimSpace(dpopNonce),
	}
	if !strings.Contains(strings.ToLower(contentType), "json") {
		return endpointError
	}
	var payload struct {
		Error           string `json:"error"`
		Description     string `json:"error_description"`
		CNonce          string `json:"c_nonce"`
		CNonceExpiresIn *int   `json:"c_nonce_expires_in"`
		Interval        int    `json:"interval"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return endpointError
	}
	endpointError.Code = sanitizeErrorText(payload.Error, maxErrorCodeLength)
	endpointError.Description = sanitizeErrorText(payload.Description, maxErrorDescriptionLength)
	endpointError.CNonce = payload.CNonce
	endpointError.CNonceExpiresIn = payload.CNonceExpiresIn
	endpointError.Interval = payload.Interval
	return endpointError
}

// decodeDraft13CredentialResponse reads a Draft 13 Section 7.3 Credential
// Response. The singular `credential` member is the Draft 13 shape; the
// `credentials` array a Final-shaped issuer may answer with is accepted when it
// holds exactly one entry, because refusing it would only turn a credential the
// wallet can read into a failure.
func decodeDraft13CredentialResponse(body []byte) (*types.Draft13CredentialResponse, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, fmt.Errorf("credential response is empty")
	}
	var payload struct {
		Credential      any    `json:"credential"`
		Credentials     []any  `json:"credentials"`
		TransactionID   string `json:"transaction_id"`
		NotificationID  string `json:"notification_id"`
		CNonce          string `json:"c_nonce"`
		CNonceExpiresIn *int   `json:"c_nonce_expires_in"`
		Interval        int    `json:"interval"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("failed to parse credential response: %w", err)
	}
	response := &types.Draft13CredentialResponse{
		TransactionID:   payload.TransactionID,
		NotificationID:  payload.NotificationID,
		CNonce:          payload.CNonce,
		CNonceExpiresIn: payload.CNonceExpiresIn,
		Interval:        payload.Interval,
	}
	raw := payload.Credential
	if raw == nil && len(payload.Credentials) > 0 {
		if len(payload.Credentials) != 1 {
			return nil, fmt.Errorf("credential response carries %d credentials, but a draft13 request asks for one", len(payload.Credentials))
		}
		entry := payload.Credentials[0]
		if object, ok := entry.(map[string]any); ok {
			raw = object["credential"]
		} else {
			raw = entry
		}
	}
	if raw == nil {
		return response, nil
	}
	credential, err := draft13CredentialString(raw)
	if err != nil {
		return nil, err
	}
	response.Credential = credential
	return response, nil
}

// draft13CredentialString renders the `credential` member. A string is the
// SD-JWT VC and JWT VC case; an object is the W3C Data Integrity case, which
// travels as the JSON document itself.
func draft13CredentialString(raw any) (string, error) {
	if text, ok := raw.(string); ok {
		return text, nil
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return "", fmt.Errorf("failed to re-encode credential: %w", err)
	}
	return string(encoded), nil
}
