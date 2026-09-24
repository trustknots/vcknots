// Package receiver provides types and structures related to receiving credentials
package receiver

import (
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

// SupportedReceivingTypes is types.SupportedReceivingTypes.
type SupportedReceivingTypes = types.SupportedReceivingTypes

// CredentialIssuerMetadata is types.CredentialIssuerMetadata.
type CredentialIssuerMetadata = types.CredentialIssuerMetadata

// CredentialConfiguration is types.CredentialConfiguration.
type CredentialConfiguration = types.CredentialConfiguration

// CredentialIssuerMetadataDisplay is types.CredentialIssuerMetadataDisplay.
type CredentialIssuerMetadataDisplay = types.CredentialIssuerMetadataDisplay

// CredentialConfigurationDisplay is types.CredentialConfigurationDisplay.
type CredentialConfigurationDisplay = types.CredentialConfigurationDisplay

// CredentialConfigurationDisplayBackgroundImage is types.CredentialConfigurationDisplayBackgroundImage.
type CredentialConfigurationDisplayBackgroundImage = types.CredentialConfigurationDisplayBackgroundImage

// DisplayLogo is types.DisplayLogo.
type DisplayLogo = types.DisplayLogo

// ProofType is types.ProofType.
type ProofType = types.ProofType

// CredentialDefinition is types.CredentialDefinition.
type CredentialDefinition = types.CredentialDefinition

// CredentialDefinitionCredentialSubject is types.CredentialDefinitionCredentialSubject.
type CredentialDefinitionCredentialSubject = types.CredentialDefinitionCredentialSubject

// CredentialDefinitionDisplay is types.CredentialDefinitionDisplay.
type CredentialDefinitionDisplay = types.CredentialDefinitionDisplay

// AuthorizationServerMetadata is types.AuthorizationServerMetadata.
type AuthorizationServerMetadata = types.AuthorizationServerMetadata

// OAuthResponseType is types.OAuthResponseType.
type OAuthResponseType = types.OAuthResponseType

// OAuthResponseMode is types.OAuthResponseMode.
type OAuthResponseMode = types.OAuthResponseMode

// OAuthGrantType is types.OAuthGrantType.
type OAuthGrantType = types.OAuthGrantType

// PkceCodeChallengeMethod is types.PkceCodeChallengeMethod.
type PkceCodeChallengeMethod = types.PkceCodeChallengeMethod

// TokenEndpointAuthMethod is types.TokenEndpointAuthMethod.
type TokenEndpointAuthMethod = types.TokenEndpointAuthMethod

// CredentialIssuanceAccessToken is types.CredentialIssuanceAccessToken.
type CredentialIssuanceAccessToken = types.CredentialIssuanceAccessToken

// Oid4vci is types.Oid4vci.
const (
	Oid4vci = types.Oid4vci
)

// OAuth 2.0 response_type values; see types.OAuthResponseType.
const (
	Code  = types.Code
	Token = types.Token
)

// OAuth 2.0 response modes; see types.OAuthResponseMode.
const (
	Query    = types.Query
	Fragment = types.Fragment
)

// OAuth 2.0 grant_type values; see types.OAuthGrantType.
const (
	AuthorizationCode = types.AuthorizationCode
	Password          = types.Password
	ClientCredentials = types.ClientCredentials
	RefreshToken      = types.RefreshToken
	JwtBearer         = types.JwtBearer
	Saml2Bearer       = types.Saml2Bearer
)

// PKCE code_challenge_method values; see types.PkceCodeChallengeMethod.
const (
	Plain = types.Plain
	S256  = types.S256
)

// Token endpoint client authentication methods; see types.TokenEndpointAuthMethod.
const (
	None                    = types.None
	ClientSecretPost        = types.ClientSecretPost
	ClientSecretBasic       = types.ClientSecretBasic
	ClientSecretJwt         = types.ClientSecretJwt
	PrivateKeyJwt           = types.PrivateKeyJwt
	TlsClientAuth           = types.TlsClientAuth
	SelfSignedTlsClientAuth = types.SelfSignedTlsClientAuth
)
