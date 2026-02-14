// Package types provides types and structures related to receiving credentials
package types

import (
	"errors"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/common"
)

// Sentinel errors for credential receiving operations
var (
	ErrInvalidMetadata           = errors.New("invalid credential issuer metadata")
	ErrUnsupportedProtocol       = errors.New("unsupported receiving protocol")
	ErrCredentialRequestFailed   = errors.New("credential request failed")
	ErrInvalidCredentialResponse = errors.New("invalid credential response")
	ErrAuthorizationFailed       = errors.New("authorization failed")
	ErrTokenRequestFailed        = errors.New("token request failed")
	ErrInvalidTokenResponse      = errors.New("invalid token response")
	ErrProofGenerationFailed     = errors.New("proof generation failed")
	ErrInvalidProofType          = errors.New("invalid or unsupported proof type")
	ErrNetworkFailed             = errors.New("network request failed")
	ErrTimeoutExpired            = errors.New("request timeout expired")
	ErrPluginNotFound            = errors.New("receiver plugin not found")
	ErrNilPlugin                 = errors.New("receiver plugin cannot be nil")
)

// ReceiverError represents an error during credential receiving operations
type ReceiverError struct {
	Protocol SupportedReceivingTypes `json:"protocol"`
	Endpoint string                  `json:"endpoint,omitempty"`
	Op       string                  `json:"operation"`
	Err      error                   `json:"error"`
}

func (e *ReceiverError) Error() string {
	if e.Endpoint != "" {
		return fmt.Sprintf("receiver %v operation %s at %s: %v", e.Protocol, e.Op, e.Endpoint, e.Err)
	}
	return fmt.Sprintf("receiver %v operation %s: %v", e.Protocol, e.Op, e.Err)
}

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

type SupportedReceivingTypes int

const (
	Oid4vci SupportedReceivingTypes = iota
	Mock                            // For mock receiver plugin that reads VC from txt files
)

type CredentialIssuerMetadata struct {
	CredentialIssuer                 string                             `json:"credential_issuer"`
	CredentialEndpoint               common.URIField                    `json:"credential_endpoint"`
	AuthorizationServers             []common.URIField                  `json:"authorization_servers,omitempty"`
	Display                          []CredentialIssuerMetadataDisplay  `json:"display,omitempty"`
	CredentialConfigurationSupported map[string]CredentialConfiguration `json:"credential_configurations_supported,omitempty"`
}

type CredentialConfiguration struct {
	Display                             *[]CredentialConfigurationDisplay `json:"display,omitempty"`
	ProofTypesSupported                 *map[string]ProofType             `json:"proof_types_supported,omitempty"`
	Format                              string                            `json:"format"`
	CredentialDefinition                *CredentialDefinition             `json:"credential_definition,omitempty"`
	CredentialSigningAlgValuesSupported []jose.SignatureAlgorithm         `json:"credential_signing_alg_values_supported,omitempty"`
}

type CredentialIssuerMetadataDisplay struct {
	Name   *string      `json:"name,omitempty"`
	Locale *string      `json:"locale,omitempty"`
	Logo   *DisplayLogo `json:"logo,omitempty"`
	MdbBio *string      `json:"mdb_bio,omitempty"`
}

type CredentialConfigurationDisplay struct {
	Name            string                                         `json:"name"`
	Locale          *string                                        `json:"locale,omitempty"`
	Logo            *DisplayLogo                                   `json:"logo,omitempty"`
	Description     *string                                        `json:"description,omitempty"`
	BackgroundColor *string                                        `json:"background_color,omitempty"`
	BackgroundImage *CredentialConfigurationDisplayBackgroundImage `json:"background_image,omitempty"`
	TextColor       *string                                        `json:"text_color,omitempty"`
}

type CredentialConfigurationDisplayBackgroundImage struct {
	Uri common.URIField `json:"uri"`
}

type DisplayLogo struct {
	Uri     common.URIField `json:"uri"`
	AltText *string         `json:"alt_text,omitempty"`
}

type ProofType struct {
	ProofSigningAlgValuesSupported []jose.SignatureAlgorithm `json:"proof_signing_alg_values_supported"`
}

type CredentialDefinition struct {
	Type              []string                               `json:"type"`
	CredentialSubject *CredentialDefinitionCredentialSubject `json:"credentialSubject,omitempty"`
}

type CredentialDefinitionCredentialSubject struct {
	Values    map[string]interface{}       `json:"values,omitempty"`
	Mandatory *bool                        `json:"mandatory,omitempty"`
	ValueType *string                      `json:"value_type,omitempty"`
	Display   *CredentialDefinitionDisplay `json:"display,omitempty"`
}

type CredentialDefinitionDisplay struct {
	Name   *string `json:"name,omitempty"`
	Locale *string `json:"locale,omitempty"`
}

type AuthorizationServerMetadata struct {
	PreAuthorizedGrantAnonymousAccessSupported         *bool                      `json:"pre-authorized_grant_anonymous_access_supported"`
	Issuer                                             common.URIField            `json:"issuer"`
	AuthorizationEndpoint                              *common.URIField           `json:"authorization_endpoint,omitempty"`
	TokenEndpoint                                      *common.URIField           `json:"token_endpoint,omitempty"`
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

type OAuthResponseType string

const (
	Code  OAuthResponseType = "code"
	Token OAuthResponseType = "token"
)

type OAuthResponseMode int

const (
	Query OAuthResponseMode = iota
	Fragment
)

type OAuthGrantType string

const (
	AuthorizationCode OAuthGrantType = "authorization_code"
	Password          OAuthGrantType = "password"
	ClientCredentials OAuthGrantType = "client_credentials"
	RefreshToken      OAuthGrantType = "refresh_token"
	JwtBearer         OAuthGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	Saml2Bearer       OAuthGrantType = "urn:ietf:params:oauth:grant-type:saml2-bearer"
)

type PkceCodeChallengeMethod string

const (
	Plain PkceCodeChallengeMethod = "plain"
	S256  PkceCodeChallengeMethod = "S256"
)

type TokenEndpointAuthMethod string

const (
	None                    TokenEndpointAuthMethod = "none"
	ClientSecretPost        TokenEndpointAuthMethod = "client_secret_post"
	ClientSecretBasic       TokenEndpointAuthMethod = "client_secret_basic"
	ClientSecretJwt         TokenEndpointAuthMethod = "client_secret_jwt"
	PrivateKeyJwt           TokenEndpointAuthMethod = "private_key_jwt"
	TlsClientAuth           TokenEndpointAuthMethod = "tls_client_auth"
	SelfSignedTlsClientAuth TokenEndpointAuthMethod = "self_signed_tls_client_auth"
)

// RFC 6749
type CredentialIssuanceAccessToken struct {
	Token           string  `json:"access_token"`
	TokenType       string  `json:"token_type"`
	ExpiresIn       int     `json:"expires_in,omitempty"`
	RefreshToken    *string `json:"refresh_token,omitempty"`
	CNonce          *string `json:"c_nonce,omitempty"`
	CNonceExpiresIn *int    `json:"c_nonce_expires_in,omitempty"`
}

// Receiver defines the interface for credential receiving components
type Receiver interface {
	// FetchIssuerMetadata fetches OID4VCI Credential Issuer Metadata
	FetchIssuerMetadata(endpoint common.URIField, receivingType SupportedReceivingTypes) (*CredentialIssuerMetadata, error)

	// FetchAuthorizationServerMetadata fetches authorization server metadata
	FetchAuthorizationServerMetadata(endpoint common.URIField, receivingType SupportedReceivingTypes) (*AuthorizationServerMetadata, error)

	// FetchAccessToken fetches access token through OID4VCI
	FetchAccessToken(receivingType SupportedReceivingTypes, endpoint common.URIField, authzCode string) (*CredentialIssuanceAccessToken, error)

	// ReceiveCredential receives credential through OID4VCI
	ReceiveCredential(
		receivingType SupportedReceivingTypes,
		endpoint common.URIField,
		format string,
		accessToken CredentialIssuanceAccessToken,
		credentialDefinition *CredentialDefinition,
		jwtProof *string,
	) (*string, error)
}
