package oid4vci

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-jose/go-jose/v4"

	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/common/observe"
	"github.com/trustknots/vcknots/wallet/internal/httpfetch"
	"github.com/trustknots/vcknots/wallet/internal/jwtproof"
	"github.com/trustknots/vcknots/wallet/internal/oid4vcijwe"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

type credentialNonceResponse struct {
	CNonce *string `json:"c_nonce"`
	Nonce  *string `json:"nonce"`
}

const maxNonceResponseBodyBytes int64 = 4 << 10

// ErrProofAlgorithmNotSupported reports that the holder key cannot produce any
// of the algorithms the Credential Issuer lists in
// proof_signing_alg_values_supported.
var ErrProofAlgorithmNotSupported = jwtproof.ErrProofAlgorithmNotSupported

// FetchNonce fetches a c_nonce from the Section 7 Nonce Endpoint. It is a
// types.Receiver method and carries no context; it binds its request to
// context.Background().
func (o *Oid4vciReceiver) FetchNonce(receivingTypes types.SupportedReceivingTypes, endpoint common.URIField) (*string, error) {
	if receivingTypes != types.Oid4vci {
		return nil, fmt.Errorf("unsupported flavor: %v", receivingTypes)
	}
	if _, err := o.normalizedProfile(); err != nil {
		return nil, err
	}

	response, err := o.do(observe.WithEndpoint(context.Background(), observe.EndpointNonce), exchange{
		method: http.MethodPost,
		url:    url.URL(endpoint),
		limit:  maxNonceResponseBodyBytes,
	})
	if errors.Is(err, httpfetch.ErrBodyTooLarge) {
		return nil, fmt.Errorf("nonce endpoint response exceeds %d bytes: %w", maxNonceResponseBodyBytes, err)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to fetch nonce: %w", err)
	}
	if !response.ok() {
		if code := response.statusError().oauthError; code != "" {
			return nil, fmt.Errorf("nonce endpoint returned status %d, error: %s", response.statusCode, code)
		}
		return nil, fmt.Errorf("nonce endpoint returned status %d", response.statusCode)
	}
	if len(response.body) == 0 {
		return nil, fmt.Errorf("nonce endpoint returned empty response")
	}

	var nonceResponse credentialNonceResponse
	if err := json.Unmarshal(response.body, &nonceResponse); err != nil {
		return nil, fmt.Errorf("failed to parse nonce response: %w", err)
	}

	if nonceResponse.CNonce != nil && *nonceResponse.CNonce != "" {
		return nonceResponse.CNonce, nil
	}
	if nonceResponse.Nonce != nil && *nonceResponse.Nonce != "" {
		return nonceResponse.Nonce, nil
	}

	return nil, fmt.Errorf("nonce response does not contain c_nonce or nonce")
}

// RequestNonce performs the OpenID4VCI 1.0 Section 7 Nonce Request. A
// DPoP-Nonce response header (Section 7.2) is returned and also kept for the
// next proof to that server.
func (o *Oid4vciReceiver) RequestNonce(ctx context.Context, endpoint common.URIField) (*types.NonceResponse, error) {
	exchanged, err := o.do(observe.WithEndpoint(ctx, observe.EndpointNonce), exchange{method: http.MethodPost, url: url.URL(endpoint)})
	if err == nil && !exchanged.ok() {
		err = exchanged.statusError()
	}
	var response types.NonceResponse
	if err == nil && len(exchanged.body) > 0 {
		if decodeErr := json.Unmarshal(exchanged.body, &response); decodeErr != nil {
			err = fmt.Errorf("failed to parse JSON: %w", decodeErr)
		}
	}
	if err != nil {
		return nil, stageError(StageNonce, fmt.Errorf("failed to fetch nonce: %w", err))
	}
	// Section 7.2: c_nonce is REQUIRED.
	if strings.TrimSpace(response.CNonce) == "" {
		return nil, fmt.Errorf("nonce response does not contain a c_nonce: %w", types.ErrNonceResponseInvalid)
	}
	response.DPoPNonce = strings.TrimSpace(exchanged.header.Get("DPoP-Nonce"))
	return &response, nil
}

// RequestCredential posts the OpenID4VCI 1.0 Section 8 Credential Request that
// body builds for cNonce. On the Section 8.3.1.2 invalid_nonce error it fetches
// a fresh c_nonce from nonceEndpoint and posts once more; with a nil
// nonceEndpoint the error is returned. A refusal is a
// *types.CredentialEndpointError.
func (o *Oid4vciReceiver) RequestCredential(ctx context.Context, endpoint common.URIField, token types.CredentialIssuanceAccessToken, cNonce string, body types.CredentialRequestBodyFactory, nonceEndpoint *common.URIField, dpop types.DPoPProofFactory) (*types.CredentialEndpointHTTPResponse, error) {
	if body == nil {
		return nil, fmt.Errorf("%w: credential request body factory is required", common.ErrInvalidInput)
	}
	ctx = observe.WithEndpoint(ctx, observe.EndpointCredential)
	response, err := o.postCredentialRequest(ctx, endpoint, token, cNonce, body, dpop)
	if err == nil || !errors.Is(err, types.ErrInvalidNonce) || nonceEndpoint == nil {
		return response, err
	}
	nonceResponse, err := o.RequestNonce(ctx, *nonceEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh c_nonce after invalid_nonce: %w", err)
	}
	return o.postCredentialRequest(ctx, endpoint, token, nonceResponse.CNonce, body, dpop)
}

// RequestDeferredCredential posts an OpenID4VCI 1.0 Section 9 Deferred
// Credential Request body encoded by EncodeCredentialRequest. A refusal, such
// as issuance_pending, is a *types.CredentialEndpointError.
func (o *Oid4vciReceiver) RequestDeferredCredential(ctx context.Context, endpoint common.URIField, token types.CredentialIssuanceAccessToken, body []byte, contentType string, dpop types.DPoPProofFactory) (*types.CredentialEndpointHTTPResponse, error) {
	return o.postCredentialEndpoint(observe.WithEndpoint(ctx, observe.EndpointDeferredCredential), endpoint, token, body, contentType, dpop)
}

// SendNotification posts an OpenID4VCI 1.0 Section 11 Notification Request.
func (o *Oid4vciReceiver) SendNotification(ctx context.Context, endpoint common.URIField, token types.CredentialIssuanceAccessToken, notification types.NotificationRequest, dpop types.DPoPProofFactory) error {
	body, err := json.Marshal(notification)
	if err != nil {
		return err
	}
	_, err = o.postProtected(observe.WithEndpoint(ctx, observe.EndpointNotification), endpoint, token, body, "application/json", dpop, httpfetch.DefaultBodyLimit)
	return err
}

// postCredentialRequest builds the body for cNonce and posts it.
func (o *Oid4vciReceiver) postCredentialRequest(ctx context.Context, endpoint common.URIField, token types.CredentialIssuanceAccessToken, cNonce string, body types.CredentialRequestBodyFactory, dpop types.DPoPProofFactory) (*types.CredentialEndpointHTTPResponse, error) {
	encoded, contentType, err := body(cNonce)
	if err != nil {
		return nil, err
	}
	return o.postCredentialEndpoint(ctx, endpoint, token, encoded, contentType, dpop)
}

func (o *Oid4vciReceiver) postCredentialEndpoint(ctx context.Context, endpoint common.URIField, token types.CredentialIssuanceAccessToken, body []byte, contentType string, dpop types.DPoPProofFactory) (*types.CredentialEndpointHTTPResponse, error) {
	response, err := o.postProtected(ctx, endpoint, token, body, contentType, dpop, httpfetch.CredentialBodyLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to post credential endpoint request: %w", err)
	}
	return &types.CredentialEndpointHTTPResponse{
		Body:        response.body,
		ContentType: response.header.Get("Content-Type"),
	}, nil
}

// EncodeCredentialRequest serializes a (Deferred) Credential Request and
// encrypts it when the issuer advertises credential_request_encryption
// (OpenID4VCI 1.0 Sections 8.2 and 10). A request carrying
// credential_response_encryption to an issuer without request encryption is
// refused: Section 8.2 requires the request to be encrypted then, so the
// response key cannot be substituted.
func (o *Oid4vciReceiver) EncodeCredentialRequest(request any, issuerMetadata *types.CredentialIssuerMetadata) ([]byte, string, error) {
	plaintext, err := json.Marshal(request)
	if err != nil {
		return nil, "", err
	}
	if issuerMetadata == nil || issuerMetadata.CredentialRequestEncryption == nil {
		if requestCarriesResponseEncryption(plaintext) {
			return nil, "", fmt.Errorf("credential_response_encryption was requested but the issuer does not advertise credential_request_encryption")
		}
		return plaintext, "application/json", nil
	}

	encryptionKey, err := selectEncryptionKey(&issuerMetadata.CredentialRequestEncryption.Jwks)
	if err != nil {
		return nil, "", err
	}
	// Section 10 (Encrypted Credential Requests and Responses): "The `alg`
	// parameter MUST be present. The JWE `alg` algorithm used MUST be equal to
	// the `alg` value of the chosen JWK." The JWE alg therefore comes from the
	// key, never from the metadata: Section 12.2.4 defines no
	// alg_values_supported member on credential_request_encryption.
	alg, err := credentialRequestEncryptionAlgorithm(encryptionKey)
	if err != nil {
		return nil, "", err
	}
	enc, err := selectSupportedEnc(issuerMetadata.CredentialRequestEncryption.EncValuesSupported)
	if err != nil {
		return nil, "", fmt.Errorf("credential request encryption: %w", err)
	}

	keyAlg, err := parseJWEKeyAlgorithm(alg)
	if err != nil {
		return nil, "", err
	}
	contentEnc, err := parseJWEContentEncryption(enc)
	if err != nil {
		return nil, "", err
	}

	encrypter, err := jose.NewEncrypter(
		contentEnc,
		jose.Recipient{
			Algorithm: keyAlg,
			Key:       encryptionKey.Key,
			KeyID:     encryptionKey.KeyID,
		},
		(&jose.EncrypterOptions{}).WithContentType("json"),
	)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create credential request encrypter: %w", err)
	}

	jwe, err := encrypter.Encrypt(plaintext)
	if err != nil {
		return nil, "", fmt.Errorf("failed to encrypt credential request: %w", err)
	}
	serialized, err := jwe.CompactSerialize()
	if err != nil {
		return nil, "", fmt.Errorf("failed to serialize credential request JWE: %w", err)
	}
	return []byte(serialized), "application/jwt", nil
}

// DecodeCredentialResponse parses an OpenID4VCI 1.0 Section 8.3 Credential
// Response or Section 9.2 Deferred Credential Response. An application/jwt
// body is a Section 10 JWE decrypted with decryptionKey (a private key or a
// *jose.JSONWebKey). A plaintext body is refused with
// types.ErrCredentialResponsePlaintext when requireEncryption is set or a
// decryptionKey is given, since a requested encryption is never downgraded.
// It checks no response shape beyond JSON well-formedness.
func (o *Oid4vciReceiver) DecodeCredentialResponse(body []byte, contentType string, decryptionKey any, requireEncryption bool) (*types.CredentialResponse, error) {
	if key, ok := decryptionKey.(*jose.JSONWebKey); ok && key == nil {
		decryptionKey = nil
	}
	payload := body
	encrypted := httpfetch.MediaTypeIs(http.Header{"Content-Type": {contentType}}, "application/jwt")
	if !encrypted && (requireEncryption || decryptionKey != nil) {
		return nil, fmt.Errorf("%w: the issuer returned an unencrypted credential response although response encryption was required", types.ErrCredentialResponsePlaintext)
	}
	if encrypted {
		if decryptionKey == nil {
			return nil, fmt.Errorf("%w: a decryption key is required for an encrypted credential response", types.ErrCredentialResponseDecrypt)
		}
		jwe, err := jose.ParseEncrypted(string(body), oid4vcijwe.KeyAlgorithms(), oid4vcijwe.ContentEncryptions())
		if err != nil {
			return nil, fmt.Errorf("%w: failed to parse credential response JWE: %w", types.ErrCredentialResponseDecrypt, err)
		}
		// go-jose inflates a "zip":"DEF" payload inside Decrypt (Section 10).
		payload, err = jwe.Decrypt(decryptionKey)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to decrypt credential response JWE: %w", types.ErrCredentialResponseDecrypt, err)
		}
	}
	var response types.CredentialResponse
	if err := json.Unmarshal(payload, &response); err != nil {
		return nil, fmt.Errorf("%w: failed to parse credential response JSON: %w", types.ErrCredentialResponseShape, err)
	}
	return &response, nil
}

// postProtected posts body to a Credential, Deferred Credential or
// Notification Endpoint with the access token and, for a DPoP-bound token, a
// DPoP proof per attempt. A non-2xx response is returned as the Section
// 8.3.1.2 *types.CredentialEndpointError, or as ErrDPoPRequired when a request
// sent with a Bearer token is asked for DPoP. An invalid_nonce refusal is
// reported as such first, so the caller can refresh the c_nonce.
func (o *Oid4vciReceiver) postProtected(ctx context.Context, endpoint common.URIField, accessToken types.CredentialIssuanceAccessToken, body []byte, contentType string, proofFactory types.DPoPProofFactory, limit int64) (*exchangeResponse, error) {
	response, err := o.postWithAccessToken(ctx, endpoint, accessToken, body, contentType, proofFactory, limit)
	if err != nil {
		return nil, err
	}
	if response.ok() {
		return response, nil
	}
	responseContentType := response.header.Get("Content-Type")
	dpopNonce := response.header.Get("DPoP-Nonce")
	if isCredentialNonceError(responseContentType, response.body) {
		return nil, newCredentialEndpointError(response.statusCode, responseContentType, response.body, dpopNonce)
	}
	if bearerTokenChallenged(&accessToken, response) {
		return nil, ErrDPoPRequired
	}
	return nil, newCredentialEndpointError(response.statusCode, responseContentType, response.body, dpopNonce)
}

// postWithAccessToken posts body with the access token in the scheme its
// token_type names. A DPoP-bound token takes a proof from proofFactory for each
// attempt; a Bearer token carries none (RFC 9449 Section 7.1 pairs the proof
// with the DPoP scheme). The response is returned whatever its status.
func (o *Oid4vciReceiver) postWithAccessToken(ctx context.Context, endpoint common.URIField, accessToken types.CredentialIssuanceAccessToken, body []byte, contentType string, proofFactory types.DPoPProofFactory, limit int64) (*exchangeResponse, error) {
	ex := exchange{
		method:      http.MethodPost,
		url:         url.URL(endpoint),
		contentType: contentType,
		body:        func() ([]byte, error) { return body, nil },
		accessToken: &accessToken,
		limit:       limit,
	}
	if authorizationScheme(accessToken.TokenType) == dpopAuthorizationScheme {
		if proofFactory == nil {
			return nil, fmt.Errorf("%w: a DPoP-bound access token needs a DPoP proof factory", ErrDPoPRequired)
		}
		ex.dpop = proofFactory
	}
	return o.do(ctx, ex)
}

// newCredentialEndpointError converts a non-2xx credential, deferred credential
// or notification response into the OpenID4VCI 1.0 §8.3.1.2 typed error (see
// also §9.2 and §11.3 for the deferred and notification error responses). The
// HTTP status is always retained. For 4xx responses served as JSON, the
// "error", "error_description" and "interval" members are parsed so callers can
// use errors.Is; any other content type (or unparseable body) leaves Code empty.
func newCredentialEndpointError(statusCode int, contentType string, body []byte, dpopNonce string) *types.CredentialEndpointError {
	credentialErr := &types.CredentialEndpointError{
		StatusCode: statusCode,
		DPoPNonce:  strings.TrimSpace(dpopNonce),
	}
	if statusCode < 400 || statusCode >= 500 || !strings.Contains(strings.ToLower(contentType), "json") {
		return credentialErr
	}
	var payload struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
		Interval    int    `json:"interval"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return credentialErr
	}
	credentialErr.Code = sanitizeErrorText(payload.Error, maxErrorCodeLength)
	credentialErr.Description = sanitizeErrorText(payload.Description, maxErrorDescriptionLength)
	credentialErr.Interval = payload.Interval
	return credentialErr
}

func firstCredentialRequestOptions(options []*types.CredentialRequestOptions) *types.CredentialRequestOptions {
	for _, option := range options {
		if option != nil {
			return option
		}
	}
	return nil
}

// isCredentialNonceError reports whether a non-2xx Credential Endpoint response
// is the OpenID4VCI 1.0 §8.3.1.2 "invalid_nonce" Credential Error Response. The
// error is read from the body, so a response that also carries a DPoP-Nonce
// header is still recognised as the c_nonce failure it names. A body that is not
// JSON cannot be a §8.3.1.2 error object.
func isCredentialNonceError(contentType string, body []byte) bool {
	if !strings.Contains(strings.ToLower(contentType), "json") {
		return false
	}
	return oauthErrorCode(body) == types.ErrInvalidNonce.Error()
}
