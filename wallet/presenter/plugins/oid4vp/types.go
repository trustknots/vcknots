package oid4vp

import (
	"encoding/json"
	"fmt"

	"github.com/go-jose/go-jose/v4"

	"github.com/trustknots/vcknots/wallet/common"
)

// PresentationDefinition is used only by the explicit Draft24 entrypoint.
type PresentationDefinition struct {
	ID string `json:"id"`
}

// OAuthAuthzRequest represents a OAuth 2.0 Authorization Request
// These fields are defined in RFC6749 and OIDC.
type OAuthAuthzRequest struct {
	// Scope is the Draft 24 scope parameter. OpenID4VP 1.0 requests use DcqlQuery.
	Scope        string                    `json:"scope,omitempty"`
	ResponseType string                    `json:"response_type"`          // required
	ClientID     string                    `json:"client_id"`              // required
	RedirectURI  string                    `json:"redirect_uri,omitempty"` // optional
	State        string                    `json:"state,omitempty"`        // conditional required in OID4VP
	Nonce        string                    `json:"nonce"`                  // required in OIDC
	ResponseMode OAuthAuthzReqResponseMode `json:"response_mode"`          // required in OID4VP, but optional in OIDC
}

// OAuthAuthzReqResponseMode is an Authorization Request response_mode value.
type OAuthAuthzReqResponseMode string

const (
	// OAuthAuthzReqResponseModeQuery indicates that the authorization response should be returned in the query string
	OAuthAuthzReqResponseModeQuery OAuthAuthzReqResponseMode = "query"
	// OAuthAuthzReqResponseModeFragment indicates that the authorization response should be returned in the fragment component of the redirect URI
	OAuthAuthzReqResponseModeFragment OAuthAuthzReqResponseMode = "fragment"
	// OAuthAuthzReqResponseModeDirectPost indicates that the authorization response should be returned as a direct POST
	// newly defined in OID4VP
	OAuthAuthzReqResponseModeDirectPost OAuthAuthzReqResponseMode = "direct_post"
	// OAuthAuthzReqResponseModeDirectPostJWT indicates that the authorization response should be returned as a JWT/JWE in a direct POST response parameter.
	OAuthAuthzReqResponseModeDirectPostJWT OAuthAuthzReqResponseMode = "direct_post.jwt"
	// OAuthAuthzReqResponseModeDCAPI indicates the authorization response is
	// returned through the W3C Digital Credentials API (OID4VP 1.0 Appendix A).
	OAuthAuthzReqResponseModeDCAPI OAuthAuthzReqResponseMode = "dc_api"
	// OAuthAuthzReqResponseModeDCAPIJWT indicates the authorization response is
	// returned through the DC API as an encrypted JWT (OID4VP 1.0 Appendix A.2).
	OAuthAuthzReqResponseModeDCAPIJWT OAuthAuthzReqResponseMode = "dc_api.jwt"
)

// DC API exchange protocol values (OID4VP 1.0 Appendix A.1). The value 1 is
// used for the version field; unsigned, signed and multi-signed requests use
// "unsigned", "signed" and "multisigned" respectively.
const (
	DCAPIProtocolUnsigned    = "openid4vp-v1-unsigned"
	DCAPIProtocolSigned      = "openid4vp-v1-signed"
	DCAPIProtocolMultiSigned = "openid4vp-v1-multisigned"
)

// OAuthAuthorizationResponse represents a OAuth 2.0 Authorization Response
// These fields are defined in RFC6749.
type OAuthAuthorizationResponse struct {
	Code  string `json:"code"`            // required
	State string `json:"state,omitempty"` // required if the state parameter was present in the client authorization request
}

// OAuthErrorResponse represents a OAuth 2.0 Error Response
// These fields are defined in RFC6749.
type OAuthAuthzErrorResponse struct {
	Error            OAuthAuthzError `json:"error"`                       // required
	ErrorDescription string          `json:"error_description,omitempty"` // optional
	ErrorURI         string          `json:"error_uri,omitempty"`         // optional
	State            string          `json:"state,omitempty"`             // required if the state parameter was present in the client authorization request
}

// OAuthAuthzError is an OAuth 2.0 or OpenID4VP authorization error code.
type OAuthAuthzError string

const (
	// InvalidRequestError indicates that the request is missing a required parameter, includes an unsupported parameter or parameter value, or is otherwise malformed.
	InvalidRequestError OAuthAuthzError = "invalid_request"
	// UnauthorizedClientError indicates that the client is not authorized to request an authorization code using this method.
	UnauthorizedClientError OAuthAuthzError = "unauthorized_client"
	// AccessDeniedError indicates that the resource owner or authorization server denied the request.
	AccessDeniedError OAuthAuthzError = "access_denied"
	// UnsupportedResponseTypeError indicates that the authorization server does not support obtaining an authorization code using this method.
	UnsupportedResponseTypeError OAuthAuthzError = "unsupported_response_type"
	// InvalidScopeError indicates that the requested scope is invalid, unknown, or malformed.
	InvalidScopeError OAuthAuthzError = "invalid_scope"
	// ServerError indicates that the authorization server encountered an unexpected condition that prevented it from fulfilling the request. (This error code is needed because a 500 Internal Server Error HTTP status code cannot be returned to the client via a HTTP redirect.)
	ServerError OAuthAuthzError = "server_error"
	// TemporarilyUnavailableError indicates that the authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server. (This error code is needed because a 503 Service Unavailable HTTP status code cannot be returned to the client via a HTTP redirect.)
	TemporarilyUnavailableError OAuthAuthzError = "temporarily_unavailable"
	// VPFormatsNotSupportedError indicates that the Wallet does not support any of the Credential formats requested by the Verifier. (defined in OID4VP)
	VPFormatsNotSupportedError OAuthAuthzError = "vp_formats_not_supported"
	// InvalidRequestURIMethodError indicates that the request_uri_method value is neither get nor post (case-sensitive). (OID4VP 1.0 §8.5)
	InvalidRequestURIMethodError OAuthAuthzError = "invalid_request_uri_method"
	// InvalidTransactionDataError indicates that a transaction_data object uses an unknown/unsupported type or is otherwise invalid. (OID4VP 1.0 §8.5)
	InvalidTransactionDataError OAuthAuthzError = "invalid_transaction_data"
	// WalletUnavailableError indicates that the Wallet is unavailable and unable to respond to the request. (OID4VP 1.0 §8.5)
	WalletUnavailableError OAuthAuthzError = "wallet_unavailable"
	// InvalidClientError indicates a problem with the Client Identifier / client_metadata relationship. (OID4VP 1.0 §8.5)
	InvalidClientError OAuthAuthzError = "invalid_client"
)

// CredentialPresentationRequest represents a OAuth 2.0 Authorization Request
// with a DCQL query for OID4VP.
// These fields are defined in the OID4VP specification and RFC6749.
type CredentialPresentationRequest struct {
	*OAuthAuthzRequest
	// RequestObjectVerification is produced by local signature/trust validation;
	// it is not accepted from or serialized into authorization request data.
	RequestObjectVerification *RequestObjectVerification `json:"-"`
	// PresentationDefinitionURI is the Draft24 presentation_definition_uri
	// parameter as it arrived. This library does not dereference it; a Wallet
	// that accepts the parameter resolves it after admitting the request.
	PresentationDefinitionURI string `json:"presentation_definition_uri,omitempty"`
	// VerifierFederation is the Trust Chain that authenticated an
	// openid_federation Verifier, signed or (when allowed) unsigned. It is
	// produced by this library, never read from request data.
	VerifierFederation     *FederationEvidence     `json:"-"`
	PresentationDefinition *PresentationDefinition `json:"presentation_definition,omitempty"`
	// RawPresentationDefinition is the Draft24 presentation_definition
	// exactly as it arrived; PresentationDefinition keeps only its id. It is
	// nil on the Final path.
	RawPresentationDefinition json.RawMessage   `json:"-"`
	DcqlQuery                 *DcqlQuery        `json:"dcql_query"`                            // required
	ClientMetadata            *VerifierMetadata `json:"client_metadata,omitempty"`             // optional
	TransactionData           []string          `json:"transaction_data,omitempty"`            // optional, to be implemented
	TransactionDataHashesAlg  string            `json:"transaction_data_hashes_alg,omitempty"` // optional, hash algorithm for transaction_data_hashes
	VerifierInfo              []any             `json:"verifier_info,omitempty"`               // optional, to be implemented
	ResponseURI               string            `json:"response_uri,omitempty"`                // optional
	// ResponseAudience is the audience for a DC API response. OID4VP 1.0
	// Appendix A.4: "The audience for the response (for example, the aud value
	// in a Key Binding JWT) MUST be the Origin, prefixed with origin:". It is
	// empty for non-DC-API requests, where client_id remains the audience.
	ResponseAudience string `json:"-"`
	// DCAPIProtocol records the DC API exchange protocol the request arrived
	// with so the response echoes it (OID4VP 1.0 Appendix A.4). Empty for
	// non-DC-API requests.
	DCAPIProtocol string `json:"-"`
}

// responseEndpoint is the endpoint the Authorization Response reaches:
// response_uri under direct_post and direct_post.jwt, which exclude
// redirect_uri (OID4VP 1.0 §8.2), and redirect_uri otherwise.
func (r *CredentialPresentationRequest) responseEndpoint() string {
	if isDirectPostMode(r.ResponseMode) {
		return r.ResponseURI
	}
	return r.RedirectURI
}

// RequestURIMethod is an OpenID4VP request_uri_method value.
type RequestURIMethod string

const (
	// RequestURIMethodGET indicates that the request_uri should be fetched using HTTP GET
	RequestURIMethodGET RequestURIMethod = "get"
	// RequestURIMethodPOST indicates that the request_uri should be fetched using HTTP POST
	RequestURIMethodPOST RequestURIMethod = "post"
)

// VerifierMetadata represents the Verifier Metadata (Client Metadata) in OID4VP.
// These fields are defined in RFC7591 and the OID4VP specification, and stated as optional.
type VerifierMetadata struct {
	RedirectURIs                        []string           `json:"redirect_uris,omitempty"`
	TokenEndpointAuthMethod             string             `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes                          []string           `json:"grant_types,omitempty"`
	ResponseTypes                       []string           `json:"response_types,omitempty"`
	ClientName                          string             `json:"client_name,omitempty"`
	ClientURI                           string             `json:"client_uri,omitempty"`
	LogoURI                             string             `json:"logo_uri,omitempty"`
	Scope                               string             `json:"scope,omitempty"`
	Contacts                            []string           `json:"contacts,omitempty"`
	ToSURI                              string             `json:"tos_uri,omitempty"`
	PolicyURI                           string             `json:"policy_uri,omitempty"`
	JwksURI                             string             `json:"jwks_uri,omitempty"`
	Jwks                                jose.JSONWebKeySet `json:"jwks,omitempty"`
	SoftwareID                          string             `json:"software_id,omitempty"`
	SoftwareVersion                     string             `json:"software_version,omitempty"`
	AuthorizationEncryptedResponseAlg   string             `json:"authorization_encrypted_response_alg,omitempty"`
	AuthorizationEncryptedResponseEnc   string             `json:"authorization_encrypted_response_enc,omitempty"`
	EncryptedResponseEncValuesSupported []string           `json:"encrypted_response_enc_values_supported,omitempty"`

	// encryptionPolicy records the response encryption rules the request
	// carrying this metadata was admitted under, so the response is encrypted
	// under the same rules. It is never read from or written to JSON.
	encryptionPolicy responseEncryptionPolicy
}

// responseEncryptionPolicy is the response encryption rule set a request was
// admitted under.
type responseEncryptionPolicy int

const (
	// encryptionPolicyUnset defers to the presenter's profile.
	encryptionPolicyUnset responseEncryptionPolicy = iota
	encryptionPolicyFinal
	encryptionPolicyHAIP
)

// FetchKeyWithKID returns the key of v.Jwks whose kid is kid, or an error when
// there is none.
func (v *VerifierMetadata) FetchKeyWithKID(kid string) (jose.JSONWebKey, error) {
	for _, key := range v.Jwks.Keys {
		if key.KeyID == kid {
			return key, nil
		}
	}
	return jose.JSONWebKey{}, fmt.Errorf("key with kid %s not found", kid)
}

// ErrPreRegisteredClientUnknown reports an Authorization Request whose
// pre-registered Client Identifier is not in this wallet's registry (OID4VP
// 1.0 §5.9.2: it "needs to be known to the Wallet in advance").
var ErrPreRegisteredClientUnknown = common.NewCodedError("pre_registered_client_unknown", "pre-registered client_id is not in the wallet registry")

// ErrPreRegisteredClientEndpointUnregistered reports a pre-registered
// client's request whose response endpoint (response_uri, or redirect_uri
// outside direct_post) is not one of the registered redirect_uris.
var ErrPreRegisteredClientEndpointUnregistered = common.NewCodedError("pre_registered_client_endpoint_unregistered", "the response endpoint is not registered for this pre-registered client")

// PreRegisteredClient is a Verifier this wallet knows before an Authorization
// Request arrives: a Client Identifier without ":" (OID4VP 1.0 §5.9.2).
type PreRegisteredClient struct {
	// ClientID is the registered Client Identifier. It may be left empty in a
	// map registration, where the map key is authoritative.
	ClientID string
	// Metadata is the registered Verifier metadata (RFC 7591 or out of band).
	// It replaces the request's metadata, and a request that also carries
	// client_metadata is refused with invalid_client (§8.5). Its RedirectURIs
	// are the only response endpoints the request may name, compared exactly;
	// a registration without them accepts no request.
	Metadata *VerifierMetadata
	// JWKS holds the keys that sign this client's Request Objects. A signed
	// Request Object is refused when it is nil.
	JWKS *jose.JSONWebKeySet
	// RequireSignedRequestObject refuses an unsigned request from this client
	// (the require_signed_request_object client metadata of RFC 9101 §10.5).
	RequireSignedRequestObject bool
}

// PreRegisteredClientResolver looks up a pre-registered Client Identifier in a
// caller-owned registry, for example a database of manually registered
// Verifiers. It returns nil, nil when the client is unknown, and an error only
// when the lookup itself failed.
type PreRegisteredClientResolver func(clientID string) (*PreRegisteredClient, error)

// GrantTypes supported by the OID4VP plugin
type GrantTypes string

const (
	// AuthorizationCodeGrantType represents the authorization_code grant type
	AuthorizationCodeGrantType GrantTypes = "authorization_code"
	// RefreshTokenGrantType represents the refresh_token grant type
	RefreshTokenGrantType GrantTypes = "refresh_token"
)

// CredentialPresentationRequestBuilder describes a builder that assembles a
// CredentialPresentationRequest from query parameters, a Request Object or a
// request_uri.
type CredentialPresentationRequestBuilder interface {
	WithQueryParams(params map[string][]string) *CredentialPresentationRequestBuilder
	WithRequestObject(obj string) *CredentialPresentationRequestBuilder
	WithRequestObjectURI(uri string, method RequestURIMethod) *CredentialPresentationRequestBuilder
	Build() (*CredentialPresentationRequest, error)
}

// UnmarshalJSON decodes verifier metadata while tolerating JWKS entries this
// library cannot represent (unknown kty, post-quantum key types, malformed
// members). RFC 7517 §5 and OpenID4VP 1.0 §8.3 require the Wallet to ignore
// unusable keys instead of rejecting the whole request; only the parseable
// keys are kept, in their original order.
func (v *VerifierMetadata) UnmarshalJSON(data []byte) error {
	type verifierMetadataAlias VerifierMetadata
	var decoded struct {
		verifierMetadataAlias
		Jwks json.RawMessage `json:"jwks,omitempty"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*v = VerifierMetadata(decoded.verifierMetadataAlias)
	v.Jwks = jose.JSONWebKeySet{}
	if len(decoded.Jwks) == 0 || string(decoded.Jwks) == "null" {
		return nil
	}
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(decoded.Jwks, &set); err != nil {
		return fmt.Errorf("client_metadata.jwks must be a JWK Set: %w", err)
	}
	for _, raw := range set.Keys {
		var key jose.JSONWebKey
		if err := key.UnmarshalJSON(raw); err != nil {
			continue
		}
		v.Jwks.Keys = append(v.Jwks.Keys, key)
	}
	return nil
}
