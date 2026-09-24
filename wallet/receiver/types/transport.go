package types

import (
	"context"
	"fmt"

	"github.com/trustknots/vcknots/wallet/common"
)

// This file declares the capabilities a receiver plugin offers to an
// OpenID4VCI issuance, one interface per concern. A wallet type-asserts a
// registered Receiver to the capability it needs.
//
// Every method that performs I/O takes a context as its first parameter and
// binds every HTTP request it makes, retries included, to it.
//
// Retry policy. An implementation retries at most once for each of these
// conditions and never otherwise:
//   - RFC 9449 Section 8: a server answering with the "use_dpop_nonce" error
//     and a DPoP-Nonce header is asked again with a proof for that nonce.
//   - OpenID4VCI 1.0 Section 8.3.1.2: a Credential Endpoint answering
//     "invalid_nonce" is asked again after a fresh c_nonce is fetched from the
//     Nonce Endpoint and the body is rebuilt for it.
//
// Every factory (DPoPProofFactory, OAuthClientAttestationHeadersFactory,
// ClientAssertionFactory, CredentialRequestBodyFactory) is called once per
// HTTP attempt, so nothing carrying a jti is ever replayed.

// PreAuthorizedCode is the grant type of the OpenID4VCI 1.0 Section 4.1.1
// Pre-Authorized Code Flow.
const PreAuthorizedCode OAuthGrantType = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

// IssuerDiscovery dereferences Credential Offers and resolves issuer and
// authorization server metadata with the plugin's HTTP client and policy.
type IssuerDiscovery interface {
	CredentialOfferFetcher
	// DiscoverCredentialIssuer resolves the OpenID4VCI 1.0 Section 12.2
	// Credential Issuer Metadata of issuer. The result satisfies the plugin's
	// profile and its credential_issuer equals issuer (Section 12.2.4).
	DiscoverCredentialIssuer(ctx context.Context, issuer common.URIField) (*CredentialIssuerMetadata, error)
	// DiscoverAuthorizationServer resolves the RFC 8414 metadata of the
	// authorization server issuer; its issuer member equals issuer (RFC 8414
	// Section 3.3).
	DiscoverAuthorizationServer(ctx context.Context, issuer common.URIField) (*AuthorizationServerMetadata, error)
}

// ClientAuthentication holds the per-attempt credentials a request to an
// authorization server carries. A nil factory sends nothing for its mechanism.
type ClientAuthentication struct {
	// DPoP builds the RFC 9449 DPoP proof.
	DPoP DPoPProofFactory
	// ClientAttestation builds the OAuth-Client-Attestation and
	// OAuth-Client-Attestation-PoP headers.
	ClientAttestation OAuthClientAttestationHeadersFactory
	// ClientAssertion builds the RFC 7523 private_key_jwt client_assertion; the
	// plugin sends it with the jwt-bearer client_assertion_type.
	ClientAssertion ClientAssertionFactory
}

// TokenRequest is an OpenID4VCI 1.0 Section 6.1 Token Request. GrantType
// selects which members are sent: AuthorizationCode sends Code, CodeVerifier
// and RedirectURI; PreAuthorizedCode sends PreAuthorizedCode and TxCode. Empty
// optional members are omitted.
type TokenRequest struct {
	GrantType         OAuthGrantType
	Code              string
	CodeVerifier      string
	RedirectURI       string
	PreAuthorizedCode string
	TxCode            string
	ClientID          string
	// AuthorizationDetails is the RFC 9396 authorization_details parameter.
	AuthorizationDetails []CredentialIssuanceAuthorizationDetail
}

// AuthorizationTransport performs the requests to the authorization server.
type AuthorizationTransport interface {
	// PushAuthorizationRequest sends an RFC 9126 Pushed Authorization Request
	// (OpenID4VCI 1.0 Section 5.1.4).
	PushAuthorizationRequest(ctx context.Context, endpoint common.URIField, request PushedAuthorizationRequest, auth ClientAuthentication) (*PushedAuthorizationResponse, error)
	// FetchClientAttestationChallenge fetches a challenge for the Client
	// Attestation PoP from the authorization server's challenge endpoint.
	FetchClientAttestationChallenge(ctx context.Context, endpoint common.URIField) (*ClientAttestationChallengeResponse, error)
	// RequestToken sends the Token Request and returns the parsed response.
	RequestToken(ctx context.Context, endpoint common.URIField, request TokenRequest, auth ClientAuthentication) (*CredentialIssuanceAccessToken, error)
}

// CredentialTransport performs the OpenID4VCI 1.0 requests to the Credential
// Issuer. The access token is sent with the scheme its token_type names:
// Bearer (RFC 6750) or DPoP (RFC 9449 Section 7.1).
type CredentialTransport interface {
	// RequestNonce performs the Section 7 Nonce Request.
	RequestNonce(ctx context.Context, endpoint common.URIField) (*NonceResponse, error)
	// RequestCredential posts the Section 8 Credential Request built by body
	// for cNonce. On "invalid_nonce" it refreshes the c_nonce from
	// nonceEndpoint and posts once more; a nil nonceEndpoint returns the error.
	RequestCredential(ctx context.Context, endpoint common.URIField, token CredentialIssuanceAccessToken, cNonce string, body CredentialRequestBodyFactory, nonceEndpoint *common.URIField, dpop DPoPProofFactory) (*CredentialEndpointHTTPResponse, error)
	// RequestDeferredCredential posts a Section 9 Deferred Credential Request
	// body, encoded by EncodeCredentialRequest.
	RequestDeferredCredential(ctx context.Context, endpoint common.URIField, token CredentialIssuanceAccessToken, body []byte, contentType string, dpop DPoPProofFactory) (*CredentialEndpointHTTPResponse, error)
	// SendNotification posts a Section 11 Notification Request.
	SendNotification(ctx context.Context, endpoint common.URIField, token CredentialIssuanceAccessToken, notification NotificationRequest, dpop DPoPProofFactory) error
	// EncodeCredentialRequest serializes a (Deferred) Credential Request and
	// encrypts it when md advertises credential_request_encryption (Section
	// 10). It returns the body and its Content-Type. It performs no I/O.
	EncodeCredentialRequest(request any, md *CredentialIssuerMetadata) ([]byte, string, error)
	// DecodeCredentialResponse parses a (Deferred) Credential Response,
	// decrypting it with decryptionKey when it is encrypted (Section 10). With
	// requireEncryption a plaintext response is an error. It performs no I/O.
	DecodeCredentialResponse(body []byte, contentType string, decryptionKey any, requireEncryption bool) (*CredentialResponse, error)
}

// OID4VCITransport is everything an OpenID4VCI 1.0 issuance needs from a
// receiver plugin.
type OID4VCITransport interface {
	IssuerDiscovery
	AuthorizationTransport
	CredentialTransport
}

// Draft13CredentialTransport performs the OpenID4VCI Draft 13 requests to the
// Credential Issuer. A refusal is reported as *Draft13CredentialEndpointError.
type Draft13CredentialTransport interface {
	// RequestDraft13Credential posts a Draft 13 Section 7.2 Credential Request.
	RequestDraft13Credential(ctx context.Context, endpoint common.URIField, token CredentialIssuanceAccessToken, request Draft13CredentialRequest, dpop DPoPProofFactory) (*Draft13CredentialResponse, error)
	// RequestDraft13DeferredCredential posts a Draft 13 Section 9 Deferred
	// Credential Request for transactionID.
	RequestDraft13DeferredCredential(ctx context.Context, endpoint common.URIField, token CredentialIssuanceAccessToken, transactionID string, dpop DPoPProofFactory) (*Draft13CredentialResponse, error)
	// SendDraft13Notification posts a Draft 13 Section 10.1 Notification
	// Request, whose body is the same as OpenID4VCI 1.0's.
	SendDraft13Notification(ctx context.Context, endpoint common.URIField, token CredentialIssuanceAccessToken, notification NotificationRequest, dpop DPoPProofFactory) error
}

// Draft13Transport is everything an OpenID4VCI Draft 13 issuance needs from a
// receiver plugin.
type Draft13Transport interface {
	IssuerDiscovery
	AuthorizationTransport
	Draft13CredentialTransport
}

// Draft13Proof is the Draft 13 Section 7.2.1 proof object; Draft 13 carries a
// single proof.
type Draft13Proof struct {
	ProofType string `json:"proof_type"`
	JWT       string `json:"jwt"`
}

// Draft13CredentialRequest is the Draft 13 Section 7.2 Credential Request. It
// names either a credential_identifier or the format and its format-specific
// members, never both.
type Draft13CredentialRequest struct {
	Format               string                `json:"format,omitempty"`
	VCT                  string                `json:"vct,omitempty"`
	CredentialDefinition *CredentialDefinition `json:"credential_definition,omitempty"`
	CredentialIdentifier string                `json:"credential_identifier,omitempty"`
	Proof                *Draft13Proof         `json:"proof,omitempty"`
}

// Draft13CredentialResponse is the Draft 13 Section 7.3 Credential Response and
// the Section 9.1 Deferred Credential Response. A well-formed response sets
// exactly one of Credential and TransactionID.
type Draft13CredentialResponse struct {
	Credential      string
	TransactionID   string
	NotificationID  string
	CNonce          string
	CNonceExpiresIn *int
	// Interval is the polling interval in seconds next to a transaction_id,
	// which some Draft 13 issuers already send (1.0 Section 8.3). Zero when
	// absent.
	Interval int
}

// Draft 13 error conditions, matched with errors.Is against a
// *Draft13CredentialEndpointError.
var (
	// ErrDraft13InvalidProof is the Section 7.3.1 invalid_proof error; the
	// error may carry a fresh c_nonce.
	ErrDraft13InvalidProof = common.NewCodedError("draft13_credential_invalid_proof", "invalid_proof")
	// ErrDraft13IssuancePending is the Section 9.2 issuance_pending error.
	ErrDraft13IssuancePending = common.NewCodedError("draft13_credential_issuance_pending", "issuance_pending")
)

// Draft13CredentialEndpointError is a Draft 13 Section 7.3.1 Credential Error
// Response, Section 9.2 Deferred Credential Error Response or Section 10.2
// Notification Error Response. Unlike 1.0, the error body may carry a fresh
// c_nonce (Section 7.3.2).
type Draft13CredentialEndpointError struct {
	StatusCode      int
	Code            string
	Description     string
	CNonce          string
	CNonceExpiresIn *int
	// Interval is the Section 9.2 interval in seconds.
	Interval int
	// DPoPNonce is the RFC 9449 Section 8.2 DPoP-Nonce response header.
	DPoPNonce string
}

// ErrorCode reports invalid_proof and issuance_pending with their own codes
// and every other refusal as draft13_credential_endpoint_failed.
func (e *Draft13CredentialEndpointError) ErrorCode() string {
	if e == nil {
		return "draft13_credential_endpoint_failed"
	}
	switch e.Code {
	case "invalid_proof":
		return "draft13_credential_invalid_proof"
	case "issuance_pending":
		return "draft13_credential_issuance_pending"
	default:
		return "draft13_credential_endpoint_failed"
	}
}

// Error implements error.
func (e *Draft13CredentialEndpointError) Error() string {
	if e == nil {
		return "draft13 credential endpoint error"
	}
	switch {
	case e.Code != "" && e.Description != "":
		return fmt.Sprintf("draft13 credential endpoint returned HTTP %d %s: %s", e.StatusCode, e.Code, e.Description)
	case e.Code != "":
		return fmt.Sprintf("draft13 credential endpoint returned HTTP %d %s", e.StatusCode, e.Code)
	default:
		return fmt.Sprintf("draft13 credential endpoint returned HTTP %d", e.StatusCode)
	}
}

// Is matches ErrDraft13InvalidProof and ErrDraft13IssuancePending by Code.
func (e *Draft13CredentialEndpointError) Is(target error) bool {
	if e == nil {
		return false
	}
	switch target {
	case ErrDraft13InvalidProof:
		return e.Code == "invalid_proof"
	case ErrDraft13IssuancePending:
		return e.Code == "issuance_pending"
	default:
		return false
	}
}
