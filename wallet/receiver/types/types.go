// Package types provides types and structures related to receiving credentials
package types

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/common"
)

// Sentinel errors for credential receiving operations
var (
	ErrInvalidMetadata           = common.NewCodedError("receiver_metadata_invalid", "invalid credential issuer metadata")
	ErrUnsupportedProtocol       = common.NewCodedError("receiver_protocol_unsupported", "unsupported receiving protocol")
	ErrCredentialRequestFailed   = common.NewCodedError("credential_request_failed", "credential request failed")
	ErrInvalidCredentialResponse = common.NewCodedError("credential_response_invalid", "invalid credential response")
	ErrAuthorizationFailed       = common.NewCodedError("authorization_failed", "authorization failed")
	ErrTokenRequestFailed        = common.NewCodedError("token_request_failed", "token request failed")
	ErrInvalidTokenResponse      = common.NewCodedError("token_response_invalid", "invalid token response")
	ErrNonceResponseInvalid      = common.NewCodedError("nonce_response_invalid", "invalid nonce response")
	ErrProofGenerationFailed     = common.NewCodedError("proof_generation_failed", "proof generation failed")
	ErrUseDPoPNonce              = common.NewCodedError("dpop_nonce_required", "use DPoP nonce")
	ErrInvalidProofType          = common.NewCodedError("proof_type_unsupported", "invalid or unsupported proof type")
	ErrNetworkFailed             = common.NewCodedError("network_request_failed", "network request failed")
	ErrTimeoutExpired            = common.NewCodedError("request_timeout_expired", "request timeout expired")
	ErrPluginNotFound            = common.NewCodedError("receiver_plugin_not_found", "receiver plugin not found")
	ErrNilPlugin                 = common.NewCodedError("receiver_plugin_nil", "receiver plugin cannot be nil")
)

// ReceiverError represents an error during credential receiving operations
type ReceiverError struct {
	Protocol SupportedReceivingTypes `json:"protocol"`
	Endpoint string                  `json:"endpoint,omitempty"`
	Op       string                  `json:"operation"`
	Err      error                   `json:"error"`
}

// Error implements error.
func (e *ReceiverError) Error() string {
	if e.Endpoint != "" {
		return fmt.Sprintf("receiver %v operation %s at %s: %v", e.Protocol, e.Op, e.Endpoint, e.Err)
	}
	return fmt.Sprintf("receiver %v operation %s: %v", e.Protocol, e.Op, e.Err)
}

// Unwrap returns the wrapped error.
func (e *ReceiverError) Unwrap() error {
	return e.Err
}

// NewReceiverError creates a new ReceiverError
func NewReceiverError(protocol SupportedReceivingTypes, endpoint, op string, err error) *ReceiverError {
	return &ReceiverError{
		Protocol: protocol,
		Endpoint: endpoint,
		Op:       op,
		Err:      err,
	}
}

// DPoPNonceError reports that a server rejected a request with use_dpop_nonce
// (RFC 9449) and carries the DPoP-Nonce value it supplied for the retry.
type DPoPNonceError struct {
	Nonce string
	Err   error
}

// NewDPoPNonceError returns a DPoPNonceError for nonce with surrounding
// whitespace trimmed. A nil err is replaced by ErrUseDPoPNonce.
func NewDPoPNonceError(nonce string, err error) *DPoPNonceError {
	if err == nil {
		err = ErrUseDPoPNonce
	}
	return &DPoPNonceError{
		Nonce: strings.TrimSpace(nonce),
		Err:   err,
	}
}

// Error implements error.
func (e *DPoPNonceError) Error() string {
	message := fmt.Sprintf("%s (use_dpop_nonce)", e.Err)
	if e.Nonce == "" {
		return message
	}
	return fmt.Sprintf("%s, DPoP-Nonce: %q", message, e.Nonce)
}

// Unwrap returns the wrapped error.
func (e *DPoPNonceError) Unwrap() error {
	return e.Err
}

// Is reports whether target is ErrUseDPoPNonce.
func (e *DPoPNonceError) Is(target error) bool {
	return target == ErrUseDPoPNonce
}

// DPoPNonceFromError returns the nonce of the first DPoPNonceError in err's
// chain and true, or "" and false when there is none.
func DPoPNonceFromError(err error) (string, bool) {
	var nonceErr *DPoPNonceError
	if errors.As(err, &nonceErr) {
		return nonceErr.Nonce, true
	}
	return "", false
}

// CredentialEndpointError is an OpenID4VCI 1.0 §8.3.1.2 error response. The
// credential, deferred credential and notification endpoints return a JSON body
// with "error" and optional "error_description"/"interval" members on failure
// (§9.2 deferred credential error response, §11.3 notification error response);
// the DPoP-Nonce response header is also retained because a caller may still
// need it to build a corrected request. §9.2 defines "interval" as the number of
// seconds the wallet must wait before polling the deferred credential endpoint
// again when error is "issuance_pending".
type CredentialEndpointError struct {
	StatusCode  int
	Code        string // error
	Description string // error_description
	DPoPNonce   string // DPoP-Nonce header, if any
	Interval    int    // §9.2: seconds to wait when Code == "issuance_pending"
}

// Sentinel errors for the OpenID4VCI 1.0 §8.3.1.2 credential endpoint error
// codes. The sentinel's message is exactly the wire value so that Error's Is
// method can match it.
var (
	ErrInvalidNonce                = common.NewCodedError("credential_endpoint_invalid_nonce", "invalid_nonce")
	ErrInvalidProof                = common.NewCodedError("credential_endpoint_invalid_proof", "invalid_proof")
	ErrIssuancePending             = common.NewCodedError("credential_endpoint_issuance_pending", "issuance_pending")
	ErrInvalidTransactionID        = common.NewCodedError("credential_endpoint_invalid_transaction_id", "invalid_transaction_id")
	ErrUnknownCredentialIdentifier = common.NewCodedError("credential_endpoint_unknown_credential_identifier", "unknown_credential_identifier")
	ErrCredentialRequestDenied     = common.NewCodedError("credential_endpoint_credential_request_denied", "credential_request_denied")
)

// ErrorCode names the Credential Endpoint refusal. An "invalid_nonce" refusal
// is a condition of its own because the Section 7 nonce refresh has already
// been attempted by the time it reaches a caller: the request carried a proof
// the issuer would not accept and no fresh c_nonce made it accepted.
func (e *CredentialEndpointError) ErrorCode() string {
	if e != nil && e.Code == ErrInvalidNonce.Error() {
		return "credential_nonce_rejected"
	}
	return "credential_endpoint_rejected"
}

// Error implements error.
func (e *CredentialEndpointError) Error() string {
	if e == nil {
		return "credential endpoint error"
	}
	message := fmt.Sprintf("unexpected status code: %d", e.StatusCode)
	if e.Code != "" {
		message += fmt.Sprintf(", error: %s", e.Code)
	}
	if e.Description != "" {
		message += fmt.Sprintf(", error_description: %s", e.Description)
	}
	if e.Interval > 0 {
		message += fmt.Sprintf(", interval: %d", e.Interval)
	}
	return message
}

// Is lets callers use errors.Is(err, ErrInvalidNonce) to branch on the §8.3.1.2
// "error" code without inspecting the response body themselves.
func (e *CredentialEndpointError) Is(target error) bool {
	if e == nil {
		return false
	}
	switch target {
	case ErrInvalidNonce:
		return e.Code == "invalid_nonce"
	case ErrInvalidProof:
		return e.Code == "invalid_proof"
	case ErrIssuancePending:
		return e.Code == "issuance_pending"
	case ErrInvalidTransactionID:
		return e.Code == "invalid_transaction_id"
	case ErrUnknownCredentialIdentifier:
		return e.Code == "unknown_credential_identifier"
	case ErrCredentialRequestDenied:
		return e.Code == "credential_request_denied"
	default:
		return false
	}
}

// SupportedReceivingTypes identifies the protocol a receiver plugin implements.
type SupportedReceivingTypes int

// SignatureAlgorithm is a JWA signature algorithm name.
type SignatureAlgorithm jose.SignatureAlgorithm

// Receiving protocols.
const (
	// Oid4vci selects the OpenID4VCI receiver plugin.
	Oid4vci SupportedReceivingTypes = iota
	// Mock selects the mock receiver plugin, which reads credentials from text files.
	Mock
)

// CredentialIssuerMetadata is the OpenID4VCI 1.0 Section 12.2 Credential
// Issuer Metadata document.
type CredentialIssuerMetadata struct {
	CredentialIssuer                 string                             `json:"credential_issuer"`
	CredentialEndpoint               common.URIField                    `json:"credential_endpoint"`
	NonceEndpoint                    *common.URIField                   `json:"nonce_endpoint,omitempty"`
	DeferredCredentialEndpoint       *common.URIField                   `json:"deferred_credential_endpoint,omitempty"`
	NotificationEndpoint             *common.URIField                   `json:"notification_endpoint,omitempty"`
	CredentialRequestEncryption      *CredentialRequestEncryption       `json:"credential_request_encryption,omitempty"`
	CredentialResponseEncryption     *CredentialResponseEncryption      `json:"credential_response_encryption,omitempty"`
	BatchCredentialIssuance          *BatchCredentialIssuance           `json:"batch_credential_issuance,omitempty"`
	AuthorizationServers             []common.URIField                  `json:"authorization_servers,omitempty"`
	Display                          []CredentialIssuerMetadataDisplay  `json:"display,omitempty"`
	CredentialConfigurationSupported map[string]CredentialConfiguration `json:"credential_configurations_supported,omitempty"`
	// SignedMetadata holds the OpenID4VCI 1.0 §12.2.3 signed Credential Issuer
	// Metadata. §12.2.3 requires the issuer to secure the metadata with a JWS
	// (alg MUST NOT be none or a MAC identifier, typ MUST be
	// openidvci-issuer-metadata+jwt) and to return it with media type
	// application/jwt; the wallet retains the compact serialization here.
	SignedMetadata string `json:"signed_metadata,omitempty"`
	// MetadataSignature records the outcome of verifying SignedMetadata so
	// callers can audit the signer. It is internal state and never serialized
	// (json:"-").
	MetadataSignature *MetadataVerification `json:"-"`
	// RawDocument is the accepted Credential Issuer Metadata document in the
	// bytes it was published in: the verified JWS payload of a §12.2.3 signed
	// response, or the body of an unsigned §12.2.2 one. §12.2.2 lets a
	// Credential Issuer publish metadata members this type does not model, and
	// §12.2.3 requires every one of them to be a top-level claim of the signed
	// payload, so a caller that must preserve the whole document — to store it,
	// to re-display it, or to read an extension — reads it here rather than
	// re-serializing the parsed struct. It is set only on an accepted document
	// and is never serialized (json:"-").
	RawDocument json.RawMessage `json:"-"`
}

// MetadataVerification records the outcome of verifying the OpenID4VCI 1.0
// §12.2.3 signed Credential Issuer Metadata. §12.2.3 requires the wallet to
// establish trust in the signer of the metadata and reject it otherwise; when
// validating the signature the wallet obtains the keys via JOSE header
// parameters such as x5c, kid or trust_chain. The fields capture the signer
// identity the metadata was accepted under; they are never serialized.
type MetadataVerification struct {
	// LeafCertificateSHA256 is the SHA-256 fingerprint of the leaf X.509
	// certificate that signed the metadata. It is the first element of
	// CertificateSHA256, kept as its own field for callers that record only
	// the signer.
	LeafCertificateSHA256 string
	// CertificateSHA256 lists the SHA-256 fingerprints of the accepted
	// certification path in chain order, leaf first, ending at the trust anchor
	// the path reached. A caller that shows the holder which chain the metadata
	// was accepted under needs the whole path, not only its ends.
	CertificateSHA256 []string
	// AnchorSHA256 is the SHA-256 fingerprint of the configured trust anchor
	// the path terminated at, which is what says under whose trust the metadata
	// was accepted when several anchors are configured. It is the last element
	// of CertificateSHA256.
	AnchorSHA256 string
	// Subject is the subject distinguished name of the signing certificate.
	Subject string
	// IssuedAt is the JWS iat: the time the Credential Issuer Metadata was
	// issued, per §12.2.3.
	IssuedAt time.Time
	// ExpiresAt is the optional JWS exp, or nil when the signed metadata does
	// not expire, per §12.2.3.
	ExpiresAt *time.Time
}

// BatchSize reports the issuer's §14.6 batch_size, defaulting to one when the
// metadata member is absent or advertises a non-positive value. A wallet must
// never request more credentials than the issuer declared.
func (m *CredentialIssuerMetadata) BatchSize() int {
	if m == nil || m.BatchCredentialIssuance == nil || m.BatchCredentialIssuance.BatchSize < 1 {
		return 1
	}
	return m.BatchCredentialIssuance.BatchSize
}

// CredentialRequestEncryption is the OpenID4VCI 1.0 Section 12.2.4
// credential_request_encryption metadata member. It has no
// alg_values_supported: Section 10 takes the JWE alg from the chosen key.
// zip_values_supported is not modelled because the wallet never compresses a
// Credential Request.
type CredentialRequestEncryption struct {
	// Jwks carries the issuer's request encryption keys.
	Jwks jose.JSONWebKeySet `json:"jwks"`
	// EncValuesSupported lists the JWE content encryption algorithms the
	// Credential Endpoint can decrypt.
	EncValuesSupported []string `json:"enc_values_supported,omitempty"`
	// EncryptionRequired is true when every Credential Request must be
	// encrypted on top of TLS.
	EncryptionRequired *bool `json:"encryption_required,omitempty"`
}

// CredentialResponseEncryption mirrors the §12.2.4
// credential_response_encryption metadata member. zip_values_supported lists
// the compression algorithms the issuer accepts for encrypted responses (see
// §10 Encrypted Credential Requests and Responses).
type CredentialResponseEncryption struct {
	AlgValuesSupported []string `json:"alg_values_supported,omitempty"`
	EncValuesSupported []string `json:"enc_values_supported,omitempty"`
	ZipValuesSupported []string `json:"zip_values_supported,omitempty"`
	EncryptionRequired *bool    `json:"encryption_required,omitempty"`
}

// BatchCredentialIssuance carries the OpenID4VCI 1.0 §14.6
// batch_credential_issuance metadata member. batch_size is the maximum number of
// Credential Responses the wallet can request in one credential request.
type BatchCredentialIssuance struct {
	BatchSize int `json:"batch_size"`
}

// CredentialConfiguration is one entry of the Credential Issuer Metadata
// credential_configurations_supported map.
type CredentialConfiguration struct {
	Display             *[]CredentialConfigurationDisplay `json:"display,omitempty"`
	ProofTypesSupported *map[string]ProofType             `json:"proof_types_supported,omitempty"`
	Scope               string                            `json:"scope,omitempty"`
	// OpenID4VCI 1.0 Section 12.2.4 defines no credential_identifier member on
	// a Credential Configuration: credential_identifier values reach the wallet
	// only in the token response's authorization_details (Section 6.2). An
	// issuer that publishes the member anyway is ignored like any other unknown
	// metadata member.
	CryptographicBindingMethodsSupported *[]string             `json:"cryptographic_binding_methods_supported,omitempty"`
	Format                               string                `json:"format"`
	CredentialDefinition                 *CredentialDefinition `json:"credential_definition,omitempty"`
	CredentialSigningAlgValuesSupported  []SignatureAlgorithm  `json:"credential_signing_alg_values_supported,omitempty"`

	// VCT is the SD-JWT VC type identifier of a "vc+sd-jwt" or "dc+sd-jwt"
	// Credential Configuration (SD-JWT VC Section 3.2.2.2). OpenID4VCI Draft 13
	// Appendix E.2.2 makes it the member a Credential Request names such a
	// credential with, so it has to survive the metadata parse.
	VCT string `json:"vct,omitempty"`
}

var coseAlgToJWA = map[int64]jose.SignatureAlgorithm{
	-8:   jose.EdDSA,
	5:    jose.HS256,
	6:    jose.HS384,
	7:    jose.HS512,
	-257: jose.RS256,
	-258: jose.RS384,
	-259: jose.RS512,
	-7:   jose.ES256,
	-9:   jose.ES256, // ESP256 (fully-specified ECDSA using P-256 and SHA-256)
	-35:  jose.ES384,
	-36:  jose.ES512,
	-37:  jose.PS256,
	-38:  jose.PS384,
	-39:  jose.PS512,
}

// UnmarshalJSON implements json.Unmarshaler. It accepts a JWA algorithm name or
// a numeric COSE algorithm identifier, which it maps to the matching JWA name.
func (c *SignatureAlgorithm) UnmarshalJSON(raw []byte) error {
	var coseID int64
	if err := json.Unmarshal(raw, &coseID); err == nil {
		// COSE algorithm identifier
		alg, ok := coseAlgToJWA[coseID]
		if !ok {
			return fmt.Errorf("unsupported COSE algorithm identifier %d", coseID)
		}
		*c = SignatureAlgorithm(alg)
		return nil
	}

	// JWA name
	var alg string
	if err := json.Unmarshal(raw, &alg); err != nil {
		return fmt.Errorf("invalid credential_signing_alg_values_supported entry: %w", err)
	}
	*c = SignatureAlgorithm(alg)
	return nil
}

// CredentialIssuerMetadataDisplay is one entry of the Credential Issuer
// Metadata display array.
type CredentialIssuerMetadataDisplay struct {
	Name   *string      `json:"name,omitempty"`
	Locale *string      `json:"locale,omitempty"`
	Logo   *DisplayLogo `json:"logo,omitempty"`
	MdbBio *string      `json:"mdb_bio,omitempty"`
}

// CredentialConfigurationDisplay is one entry of a Credential
// Configuration's display array.
type CredentialConfigurationDisplay struct {
	Name            string                                         `json:"name"`
	Locale          *string                                        `json:"locale,omitempty"`
	Logo            *DisplayLogo                                   `json:"logo,omitempty"`
	Description     *string                                        `json:"description,omitempty"`
	BackgroundColor *string                                        `json:"background_color,omitempty"`
	BackgroundImage *CredentialConfigurationDisplayBackgroundImage `json:"background_image,omitempty"`
	TextColor       *string                                        `json:"text_color,omitempty"`
}

// CredentialConfigurationDisplayBackgroundImage is the background_image member
// of a CredentialConfigurationDisplay.
type CredentialConfigurationDisplayBackgroundImage struct {
	Uri common.URIField `json:"uri"`
}

// DisplayLogo is the logo member of a display entry.
type DisplayLogo struct {
	Uri     common.URIField `json:"uri"`
	AltText *string         `json:"alt_text,omitempty"`
}

// ProofType is one entry of a Credential Configuration's
// proof_types_supported map.
type ProofType struct {
	ProofSigningAlgValuesSupported []jose.SignatureAlgorithm `json:"proof_signing_alg_values_supported"`
	// KeyAttestationsRequired is the OpenID4VCI 1.0 Appendix D
	// proof_types_supported.jwt.key_attestations_required object. Its presence
	// (even when empty) tells the wallet a key attestation is required.
	KeyAttestationsRequired *KeyAttestationsRequired `json:"key_attestations_required,omitempty"`
}

// KeyAttestationsRequired carries the OpenID4VCI 1.0 Appendix D
// key_attestations_required constraints. Both members are optional.
type KeyAttestationsRequired struct {
	KeyStorage         []string `json:"key_storage,omitempty"`
	UserAuthentication []string `json:"user_authentication,omitempty"`
}

// CredentialDefinition is the credential_definition member that describes a
// W3C Verifiable Credential by its type and credentialSubject. Context is the
// @context of an ldp_vc (OpenID4VCI Appendix A.1.2).
type CredentialDefinition struct {
	Context           []any                                  `json:"@context,omitempty"`
	Type              []string                               `json:"type"`
	CredentialSubject *CredentialDefinitionCredentialSubject `json:"credentialSubject,omitempty"`
}

// CredentialDefinitionCredentialSubject is the credentialSubject member of a
// CredentialDefinition.
type CredentialDefinitionCredentialSubject struct {
	Values    map[string]interface{}       `json:"values,omitempty"`
	Mandatory *bool                        `json:"mandatory,omitempty"`
	ValueType *string                      `json:"value_type,omitempty"`
	Display   *CredentialDefinitionDisplay `json:"display,omitempty"`
}

// CredentialDefinitionDisplay is a display entry of a
// CredentialDefinitionCredentialSubject.
type CredentialDefinitionDisplay struct {
	Name   *string `json:"name,omitempty"`
	Locale *string `json:"locale,omitempty"`
}

// AuthorizationServerMetadata is the RFC 8414 OAuth 2.0 Authorization Server
// Metadata document, including the OpenID4VCI and attestation-based client
// authentication members the wallet reads.
type AuthorizationServerMetadata struct {
	PreAuthorizedGrantAnonymousAccessSupported *bool           `json:"pre-authorized_grant_anonymous_access_supported"`
	Issuer                                     common.URIField `json:"issuer"`
	// AuthorizationResponseIssParameterSupported advertises RFC 9207 support:
	// the authorization response then carries iss, which the wallet validates.
	AuthorizationResponseIssParameterSupported         *bool                      `json:"authorization_response_iss_parameter_supported,omitempty"`
	AuthorizationEndpoint                              *common.URIField           `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                                      *common.URIField           `json:"token_endpoint,omitempty"`
	PushedAuthorizationRequestEndpoint                 *common.URIField           `json:"pushed_authorization_request_endpoint,omitempty"`
	ChallengeEndpoint                                  *common.URIField           `json:"challenge_endpoint,omitempty"`
	DPoPSigningAlgValuesSupported                      *[]jose.SignatureAlgorithm `json:"dpop_signing_alg_values_supported,omitempty"`
	JwksUri                                            *common.URIField           `json:"jwks_uri,omitempty"`
	RegistrationEndpoint                               *common.URIField           `json:"registration_endpoint,omitempty"`
	ScopesSupported                                    *[]string                  `json:"scopes_supported,omitempty"`
	ResponseTypesSupported                             []OAuthResponseType        `json:"response_types_supported"`
	ResponseModesSupported                             *[]OAuthResponseMode       `json:"response_modes_supported,omitempty"`
	GrantTypesSupported                                *[]OAuthGrantType          `json:"grant_types_supported,omitempty"`
	TokenEndpointAuthMethodsSupported                  *[]TokenEndpointAuthMethod `json:"token_endpoint_auth_methods_supported,omitempty"`
	TokenEndpointAuthSigningAlgValuesSupported         *[]jose.SignatureAlgorithm `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	ServiceDocumentation                               *common.URIField           `json:"service_documentation,omitempty"`
	UiLocalesSupported                                 *[]string                  `json:"ui_locales_supported,omitempty"`
	OpPolicyUri                                        *common.URIField           `json:"op_policy_uri,omitempty"`
	OpTosUri                                           *common.URIField           `json:"op_tos_uri,omitempty"`
	RevocationEndpoint                                 *common.URIField           `json:"revocation_endpoint,omitempty"`
	RevocationEndpointAuthMethodsSupported             *[]TokenEndpointAuthMethod `json:"revocation_endpoint_auth_methods_supported,omitempty"`
	RevocationEndpointAuthSigningAlgValuesSupported    *[]jose.SignatureAlgorithm `json:"revocation_endpoint_auth_signing_alg_values_supported,omitempty"`
	IntrospectionEndpoint                              *common.URIField           `json:"introspection_endpoint,omitempty"`
	IntrospectionEndpointAuthMethodsSupported          *[]TokenEndpointAuthMethod `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	IntrospectionEndpointAuthSigningAlgValuesSupported *[]jose.SignatureAlgorithm `json:"introspection_endpoint_auth_signing_alg_values_supported,omitempty"`
	CodeChallengeMethodsSupported                      *[]PkceCodeChallengeMethod `json:"code_challenge_methods_supported,omitempty"`
}

// OAuthResponseType is an OAuth 2.0 response_type value.
type OAuthResponseType string

// OAuth 2.0 response_type values.
const (
	// Code is the "code" response type.
	Code OAuthResponseType = "code"
	// Token is the "token" response type.
	Token OAuthResponseType = "token"
)

// OAuthResponseMode identifies an OAuth 2.0 response mode.
type OAuthResponseMode int

// OAuth 2.0 response modes.
const (
	// Query returns authorization response parameters in the query string.
	Query OAuthResponseMode = iota
	// Fragment returns authorization response parameters in the URI fragment.
	Fragment
	// OtherResponseMode stands for a response mode this package does not
	// name, such as form_post or a JARM mode, read from server metadata.
	OtherResponseMode OAuthResponseMode = -1
)

// UnmarshalJSON reads a response mode as the string RFC 8414
// response_modes_supported carries.
func (m *OAuthResponseMode) UnmarshalJSON(data []byte) error {
	var name string
	if err := json.Unmarshal(data, &name); err != nil {
		return fmt.Errorf("response mode must be a string: %w", err)
	}
	switch name {
	case "query":
		*m = Query
	case "fragment":
		*m = Fragment
	default:
		*m = OtherResponseMode
	}
	return nil
}

// MarshalJSON writes Query and Fragment by name. OtherResponseMode has no
// name to write and is refused.
func (m OAuthResponseMode) MarshalJSON() ([]byte, error) {
	switch m {
	case Query:
		return []byte(`"query"`), nil
	case Fragment:
		return []byte(`"fragment"`), nil
	default:
		return nil, fmt.Errorf("response mode %d has no name", int(m))
	}
}

// OAuthGrantType is an OAuth 2.0 grant_type value.
type OAuthGrantType string

// OAuth 2.0 grant_type values.
const (
	// AuthorizationCode is the authorization code grant (RFC 6749).
	AuthorizationCode OAuthGrantType = "authorization_code"
	// Password is the resource owner password credentials grant (RFC 6749).
	Password OAuthGrantType = "password"
	// ClientCredentials is the client credentials grant (RFC 6749).
	ClientCredentials OAuthGrantType = "client_credentials"
	// RefreshToken is the refresh token grant (RFC 6749).
	RefreshToken OAuthGrantType = "refresh_token"
	// JwtBearer is the JWT bearer authorization grant (RFC 7523).
	JwtBearer OAuthGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	// Saml2Bearer is the SAML 2.0 bearer authorization grant (RFC 7522).
	Saml2Bearer OAuthGrantType = "urn:ietf:params:oauth:grant-type:saml2-bearer"
)

// PkceCodeChallengeMethod is an RFC 7636 PKCE code_challenge_method value.
type PkceCodeChallengeMethod string

// PKCE code_challenge_method values.
const (
	// Plain is the "plain" code challenge method.
	Plain PkceCodeChallengeMethod = "plain"
	// S256 is the "S256" code challenge method.
	S256 PkceCodeChallengeMethod = "S256"
)

// TokenEndpointAuthMethod is an OAuth 2.0 token endpoint client
// authentication method.
type TokenEndpointAuthMethod string

// Token endpoint client authentication methods.
const (
	// None sends no client authentication.
	None TokenEndpointAuthMethod = "none"
	// ClientSecretPost sends the client secret in the request body.
	ClientSecretPost TokenEndpointAuthMethod = "client_secret_post"
	// ClientSecretBasic sends the client secret with HTTP Basic authentication.
	ClientSecretBasic TokenEndpointAuthMethod = "client_secret_basic"
	// ClientSecretJwt authenticates with a JWT signed with the client secret.
	ClientSecretJwt TokenEndpointAuthMethod = "client_secret_jwt"
	// PrivateKeyJwt authenticates with a JWT signed with the client's private key.
	PrivateKeyJwt TokenEndpointAuthMethod = "private_key_jwt"
	// TlsClientAuth authenticates with a PKI-bound mutual TLS certificate (RFC 8705).
	TlsClientAuth TokenEndpointAuthMethod = "tls_client_auth"
	// SelfSignedTlsClientAuth authenticates with a self-signed mutual TLS
	// certificate (RFC 8705).
	SelfSignedTlsClientAuth TokenEndpointAuthMethod = "self_signed_tls_client_auth"
)

// RFC 9396 (Rich Authorization Requests)
type CredentialIssuanceAuthorizationDetail struct {
	Type string `json:"type,omitempty"`
	// CredentialConfigurationID is the OpenID4VCI 1.0 §6.2 token response
	// member that ties the credential_identifiers to the Credential
	// Configuration requested with authorization_details.
	CredentialConfigurationID string   `json:"credential_configuration_id,omitempty"`
	CredentialIdentifiers     []string `json:"credential_identifiers,omitempty"`
}

// AuthorizationDetailTypeOpenIDCredential is the authorization_details type
// OpenID4VCI uses to request a Credential.
const AuthorizationDetailTypeOpenIDCredential = "openid_credential"

// ClientAssertionTypeJWTBearer is the client_assertion_type value used for
// private_key_jwt (and client_secret_jwt) client authentication per RFC 7523.
const ClientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// CredentialIssuanceAccessToken is a token endpoint response: the access token
// and the OpenID4VCI members returned with it.
type CredentialIssuanceAccessToken struct {
	Token                string                                  `json:"access_token"`
	TokenType            string                                  `json:"token_type"`
	ExpiresIn            int                                     `json:"expires_in,omitempty"`
	RefreshToken         *string                                 `json:"refresh_token,omitempty"`
	CNonce               *string                                 `json:"c_nonce,omitempty"`
	CNonceExpiresIn      *int                                    `json:"c_nonce_expires_in,omitempty"`
	AuthorizationDetails []CredentialIssuanceAuthorizationDetail `json:"authorization_details,omitempty"`
}

// CredentialRequestOptions carries optional per-request settings for
// Receiver.ReceiveCredential. DPoPProofJWT, when set, is sent as the DPoP proof.
type CredentialRequestOptions struct {
	DPoPProofJWT *string
}

// TokenRequestConfig holds the token request settings assembled from
// TokenRequestOption values.
type TokenRequestConfig struct {
	DPoPProof       string
	ClientID        string
	ClientAssertion string
}

// TokenRequestOption configures a TokenRequestConfig.
type TokenRequestOption func(*TokenRequestConfig)

// NewTokenRequestConfig returns a TokenRequestConfig with opts applied in
// order, skipping nil options.
func NewTokenRequestConfig(opts ...TokenRequestOption) *TokenRequestConfig {
	cfg := &TokenRequestConfig{}
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}
	return cfg
}

// WithDPoPProof sets the DPoP proof sent with the token request.
func WithDPoPProof(proof string) TokenRequestOption {
	return func(cfg *TokenRequestConfig) {
		cfg.DPoPProof = proof
	}
}

// WithClientAssertion sets the private_key_jwt client authentication parameters.
// When set, the token request includes client_id, client_assertion and
// client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer.
func WithClientAssertion(clientID, assertion string) TokenRequestOption {
	return func(cfg *TokenRequestConfig) {
		cfg.ClientID = clientID
		cfg.ClientAssertion = assertion
	}
}

// WithClientID sets the client_id sent with the token request without any
// client authentication. client_id is OPTIONAL for the pre-authorized code
// grant, so this identifies the client to an authorization server that expects
// to know who is asking without requiring the client to authenticate.
func WithClientID(clientID string) TokenRequestOption {
	return func(cfg *TokenRequestConfig) {
		cfg.ClientID = clientID
	}
}

// ResolveTokenEndpointURL returns endpoint as the authorization server
// metadata published it (RFC 8414 Section 2).
//
// Deprecated: use the token_endpoint value as published.
func ResolveTokenEndpointURL(endpoint common.URIField) string {
	return endpoint.String()
}

// PushedAuthorizationRequest holds the parameters of an RFC 9126 pushed
// authorization request.
type PushedAuthorizationRequest struct {
	ResponseType string
	ClientID     string
	RedirectURI  string
	// Scope is the OAuth 2.0 scope parameter. OpenID4VCI 1.0 §5.1.2 uses it to
	// select the Credential Configuration; empty omits the parameter.
	Scope string
	// AuthorizationDetails is the RFC 9396 §2 authorization_details JSON array
	// parameter. OpenID4VCI 1.0 §5.1.1 uses entries of type
	// openid_credential with credential_configuration_id to request a
	// Credential Configuration. Empty omits the parameter.
	AuthorizationDetails []map[string]any
	State                string
	CodeChallenge        string
	CodeChallengeMethod  string
	IssuerState          string
}

// PushedAuthorizationResponse is the RFC 9126 pushed authorization response.
type PushedAuthorizationResponse struct {
	RequestURI string `json:"request_uri"`
	ExpiresIn  int    `json:"expires_in,omitempty"`
}

// ClientAssertionFactory builds a client_assertion for one HTTP attempt; RFC
// 7523 Section 3 requires a unique jti per assertion.
type ClientAssertionFactory func() (string, error)

// ClientAttestationChallengeResponse is the response of the authorization
// server's challenge endpoint used for attestation-based client authentication.
type ClientAttestationChallengeResponse struct {
	AttestationChallenge string `json:"attestation_challenge,omitempty"`
}

// OAuthClientAttestationHeaders holds the OAuth-Client-Attestation and
// OAuth-Client-Attestation-PoP header values sent with a request.
type OAuthClientAttestationHeaders struct {
	ClientAttestation    string
	ClientAttestationPop string
}

// NonceResponse is the OpenID4VCI 1.0 §7.2 Nonce Response.
type NonceResponse struct {
	// CNonce is the §7.2 c_nonce: "REQUIRED. String containing a challenge to
	// be used when creating a proof of possession of the key".
	CNonce string `json:"c_nonce"`
	// CNonceExpiresIn is the lifetime in seconds an issuer may advertise
	// alongside c_nonce.
	CNonceExpiresIn *int `json:"c_nonce_expires_in,omitempty"`
	// DPoPNonce is the RFC 9449 §8.2 DPoP-Nonce response header value, not a
	// body member, hence json:"-". §7.2 Nonce Response: "The Credential Issuer
	// MAY provide a DPoP nonce in an HTTP header as defined in Section 8.2 of
	// [@!RFC9449]. In this case, the Wallet uses the new nonce value in the
	// DPoP proof when presenting an access token at the Credential Endpoint."
	// It is empty when the Nonce Endpoint sent no such header.
	DPoPNonce string `json:"-"`
}

// CredentialRequest is the OpenID4VCI 1.0 Section 8.2 Credential Request body.
type CredentialRequest struct {
	CredentialConfigurationID    string                               `json:"credential_configuration_id,omitempty"`
	Proofs                       *CredentialProofs                    `json:"proofs,omitempty"`
	CredentialResponseEncryption *CredentialResponseEncryptionRequest `json:"credential_response_encryption,omitempty"`
}

// CredentialProofs is the proofs member of a Credential Request.
type CredentialProofs struct {
	JWT []string `json:"jwt,omitempty"`
}

// CredentialResponseEncryptionRequest is the credential_response_encryption
// member of a Credential Request: the key and content encryption algorithm the
// issuer is to encrypt the response with.
type CredentialResponseEncryptionRequest struct {
	Jwk jose.JSONWebKey `json:"jwk"`
	Enc string          `json:"enc"`
}

// CredentialResponse is an OpenID4VCI Credential Response or Deferred
// Credential Response body.
type CredentialResponse struct {
	Credential     any     `json:"credential,omitempty"`
	Credentials    []any   `json:"credentials,omitempty"`
	TransactionID  string  `json:"transaction_id,omitempty"`
	NotificationID string  `json:"notification_id,omitempty"`
	CNonce         *string `json:"c_nonce,omitempty"`
	// Interval is the §9.1/§9.2 polling interval in seconds the issuer returns
	// alongside a deferred transaction_id. Zero when absent.
	Interval int `json:"interval,omitempty"`
}

// Credential Response decoding errors (OpenID4VCI 1.0 Sections 8.3 and 10).
var (
	// ErrCredentialResponsePlaintext reports a plaintext Credential Response
	// where an encrypted one was required or requested.
	ErrCredentialResponsePlaintext = common.NewCodedError("credential_response_plaintext", "credential response was not encrypted")
	// ErrCredentialResponseDecrypt reports an encrypted Credential Response
	// that could not be decrypted.
	ErrCredentialResponseDecrypt = common.NewCodedError("credential_response_decrypt_failed", "credential response JWE could not be decrypted")
	// ErrCredentialResponseShape reports a Credential Response that is not
	// well-formed.
	ErrCredentialResponseShape = common.NewCodedError("credential_response_shape_invalid", "credential response has an invalid shape")
)

// DeferredCredentialRequest is the OpenID4VCI Deferred Credential Request body.
type DeferredCredentialRequest struct {
	TransactionID string `json:"transaction_id"`
}

// NotificationRequest is the OpenID4VCI 1.0 §11.1 Notification Request body.
type NotificationRequest struct {
	NotificationID   string `json:"notification_id"`
	Event            string `json:"event"`
	EventDescription string `json:"event_description,omitempty"`
}

// Receiver defines the interface for credential receiving components
type Receiver interface {
	// FetchIssuerMetadata fetches OID4VCI Credential Issuer Metadata
	FetchIssuerMetadata(endpoint common.URIField, receivingType SupportedReceivingTypes) (*CredentialIssuerMetadata, error)

	// FetchAuthorizationServerMetadata fetches authorization server metadata
	FetchAuthorizationServerMetadata(endpoint common.URIField, receivingType SupportedReceivingTypes) (*AuthorizationServerMetadata, error)

	// FetchAccessToken fetches access token through OID4VCI
	FetchAccessToken(receivingType SupportedReceivingTypes, endpoint common.URIField, authzCode string, txCode string, opts ...TokenRequestOption) (*CredentialIssuanceAccessToken, error)

	// FetchNonce fetches nonce from the issuer nonce endpoint
	FetchNonce(receivingType SupportedReceivingTypes, endpoint common.URIField) (*string, error)

	// ReceiveCredential receives credential through OID4VCI
	ReceiveCredential(
		receivingType SupportedReceivingTypes,
		endpoint common.URIField,
		credentialConfigurationID string,
		credentialIdentifier *string,
		accessToken CredentialIssuanceAccessToken,
		credentialDefinition *CredentialDefinition,
		jwtProof *string,
		options ...*CredentialRequestOptions,
	) (*string, error)
}

// DPoPProofFactory builds a DPoP proof JWT for one HTTP attempt, embedding the
// server-provided nonce when it is not empty.
type DPoPProofFactory func(nonce string) (string, error)

// CredentialRequestBodyFactory builds the credential request body (already
// encoded, including any JWE wrapping) for a given c_nonce. OpenID4VCI 1.0
// §8.3.1 / §8.3.1.2 requires the wallet to embed the current c_nonce in the
// proof when the issuer supplied one; on "invalid_nonce" the wallet SHOULD
// rebuild the proof with a fresh c_nonce from the nonce endpoint.
type CredentialRequestBodyFactory func(cNonce string) (body []byte, contentType string, err error)

// OAuthClientAttestationHeadersFactory builds the client attestation headers
// for one HTTP attempt.
type OAuthClientAttestationHeadersFactory func() (OAuthClientAttestationHeaders, error)

// CredentialEndpointHTTPResponse is the body and Content-Type of a successful
// Credential or Deferred Credential Endpoint response, before decoding.
type CredentialEndpointHTTPResponse struct {
	Body        []byte
	ContentType string
}

// CredentialOfferFetcher is an optional receiver capability: it dereferences
// an OpenID4VCI 1.0 Section 4.1.3 credential_offer_uri with the plugin's own
// HTTP client and transport policy and returns the Credential Offer Object.
type CredentialOfferFetcher interface {
	FetchCredentialOffer(ctx context.Context, uri common.URIField) ([]byte, error)
}

// HTTPSchemePolicy is an optional receiver capability reporting whether the
// plugin accepts plain http endpoints, so a caller validating an identifier
// itself applies the same policy.
type HTTPSchemePolicy interface {
	HTTPAllowed() bool
}
