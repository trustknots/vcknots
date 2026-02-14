// Package receiver provides types and structures related to receiving credentials
package receiver

import (
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

// Re-export types for backward compatibility
type SupportedReceivingTypes = types.SupportedReceivingTypes
type CredentialIssuerMetadata = types.CredentialIssuerMetadata
type CredentialConfiguration = types.CredentialConfiguration
type CredentialIssuerMetadataDisplay = types.CredentialIssuerMetadataDisplay
type CredentialConfigurationDisplay = types.CredentialConfigurationDisplay
type CredentialConfigurationDisplayBackgroundImage = types.CredentialConfigurationDisplayBackgroundImage
type DisplayLogo = types.DisplayLogo
type ProofType = types.ProofType
type CredentialDefinition = types.CredentialDefinition
type CredentialDefinitionCredentialSubject = types.CredentialDefinitionCredentialSubject
type CredentialDefinitionDisplay = types.CredentialDefinitionDisplay
type AuthorizationServerMetadata = types.AuthorizationServerMetadata
type OAuthResponseType = types.OAuthResponseType
type OAuthResponseMode = types.OAuthResponseMode
type OAuthGrantType = types.OAuthGrantType
type PkceCodeChallengeMethod = types.PkceCodeChallengeMethod
type TokenEndpointAuthMethod = types.TokenEndpointAuthMethod
type CredentialIssuanceAccessToken = types.CredentialIssuanceAccessToken

// Re-export constants for backward compatibility
const (
	Oid4vci = types.Oid4vci
)

const (
	Code  = types.Code
	Token = types.Token
)

const (
	Query    = types.Query
	Fragment = types.Fragment
)

const (
	AuthorizationCode = types.AuthorizationCode
	Password          = types.Password
	ClientCredentials = types.ClientCredentials
	RefreshToken      = types.RefreshToken
	JwtBearer         = types.JwtBearer
	Saml2Bearer       = types.Saml2Bearer
)

const (
	Plain = types.Plain
	S256  = types.S256
)

const (
	None                    = types.None
	ClientSecretPost        = types.ClientSecretPost
	ClientSecretBasic       = types.ClientSecretBasic
	ClientSecretJwt         = types.ClientSecretJwt
	PrivateKeyJwt           = types.PrivateKeyJwt
	TlsClientAuth           = types.TlsClientAuth
	SelfSignedTlsClientAuth = types.SelfSignedTlsClientAuth
)
