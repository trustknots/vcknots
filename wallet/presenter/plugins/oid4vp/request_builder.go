package oid4vp

import (
	"encoding/base64"
	"fmt"
	"strings"

	commonX509 "github.com/trustknots/vcknots/wallet/common/x509"
	"github.com/trustknots/vcknots/wallet/profile"
)

// requestBuilder parses and authenticates one OpenID4VP 1.0 Authorization
// Request.
type requestBuilder struct {
	requestCore
	// policy is the presenter configuration of this parse. It is a pointer
	// so that requestBuilder stays comparable; nil is the zero policy.
	policy *builderPolicy
}

// builderPolicy is the part of the presenter configuration a requestBuilder
// reads.
type builderPolicy struct {
	requestURIPost requestURIPostSettings
	// supportedTransactionDataTypes lists the transaction_data types the
	// wallet processes (OID4VP 1.0 §5.1).
	supportedTransactionDataTypes []string
}

// settings returns the builder's policy, or the zero policy.
func (b *requestBuilder) settings() builderPolicy {
	if b.policy == nil {
		return builderPolicy{}
	}
	return *b.policy
}

// NewRequestBuilder creates a builder for OpenID4VP 1.0 Authorization
// Requests under profile.Final(). WithProfile selects another profile.
func NewRequestBuilder() *requestBuilder {
	core := newRequestCore()
	// OID4VP 1.0 §5.1 requires a unique kid on every client_metadata.jwks
	// member.
	core.requireClientMetadataJWKKeyIDs = true
	return &requestBuilder{requestCore: core}
}

// WithProfile selects the OpenID4VP 1.0 profile whose Options the builder
// applies. A draft profile is recorded as a validation error and surfaces
// from Build.
func (b *requestBuilder) WithProfile(p profile.Profile) *requestBuilder {
	if err := p.RequireFinalVersion(); err != nil {
		b.errValidation = fmt.Errorf("invalid OID4VP profile: %w", err)
		return b
	}
	b.options = p.Options()
	return b
}

func (b *requestBuilder) validate() error {
	if b.errValidation != nil {
		return b.errValidation
	}
	if b.req.DcqlQuery == nil || len(b.req.DcqlQuery.Credentials) == 0 {
		return newAuthorizationRequestError(InvalidRequestError, "dcql_query is required")
	}
	if b.req.ResponseType == "" {
		return newAuthorizationRequestError(InvalidRequestError, "response_type is required")
	}
	if b.req.ResponseType != "vp_token" {
		// OID4VP 1.0 §5.6 defines the Response Type vp_token; §8 Table 1 leaves
		// the VP Token behavior unspecified for any other value. This wallet
		// presents vp_token only and rejects the others as invalid_request.
		return newAuthorizationRequestError(InvalidRequestError, "response_type must be vp_token, got %q", b.req.ResponseType)
	}
	if b.req.ClientID == "" && b.requestSource != sourceDCAPIUnsigned {
		return newAuthorizationRequestError(InvalidRequestError, "client_id is required")
	}

	// OID4VP 1.0 Appendix A.2: a DC API request uses dc_api or dc_api.jwt, and
	// those modes return the response through the platform, not to a URI.
	dcAPIMode := isDCAPIMode(b.req.ResponseMode)
	if b.requestSource.isDCAPI() && !dcAPIMode {
		return newAuthorizationRequestError(InvalidRequestError, "a Digital Credentials API request must use response_mode dc_api or dc_api.jwt, got %q", b.req.ResponseMode)
	}
	if !b.requestSource.isDCAPI() && dcAPIMode {
		return newAuthorizationRequestError(InvalidRequestError, "response_mode %s is only valid over the Digital Credentials API", b.req.ResponseMode)
	}
	if !isDirectPostMode(b.req.ResponseMode) && !dcAPIMode && b.req.RedirectURI == "" {
		return newAuthorizationRequestError(InvalidRequestError, "redirect_uri is required")
	}
	if b.req.Nonce == "" {
		return newAuthorizationRequestError(InvalidRequestError, "%w", ErrNonceRequired)
	}
	if isDirectPostMode(b.req.ResponseMode) {
		if _, err := parseResponseURI(b.req.ResponseURI, b.allowHTTP); err != nil {
			return newAuthorizationRequestError(InvalidRequestError, "%v", err)
		}
	}
	return nil
}

// WithQueryParams populates the CredentialPresentationRequest fields from URL query parameters.
func (b *requestBuilder) WithQueryParams(params map[string][]string) *requestBuilder {
	if b.errValidation != nil {
		return b
	}

	b.requestSource = sourceQuery
	b.queryParams = params

	singleParams := make(map[string]any)
	for key, values := range params {
		if len(values) > 1 {
			b.errValidation = fmt.Errorf("multiple values provided for parameter: %s", key)
			return b
		}
		singleParams[key] = values[0]
	}

	// A Client Identifier authenticated only by a signed Request Object is
	// refused in plain parameters before anything else is read (OID4VP 1.0
	// §5.9.3).
	if value, isString := singleParams["client_id"].(string); isString {
		parsed, err := b.parseClientID(strings.TrimSpace(value))
		if err == nil && parsed.RequiresRequestObjectSignature() {
			b.errValidation = newAuthorizationRequestError(InvalidRequestError, "%w", ErrRequestObjectSignatureRequired)
			return b
		}
		// Only the redirect_uri prefix binds the Response URI before the
		// request is authenticated (OID4VP 1.0 §5.9.3).
		b.errorResponseAllowed = err == nil && parsed.prefix == OID4VPClientIDPrefixRedirectURI
	}

	b.setParamsWithAnyMap(singleParams)

	if err := b.validate(); err != nil {
		b.errValidation = err
		return b
	}

	return b
}

// WithRequestObjectURI fetches the Request Object from request_uri with the
// given method (OID4VP 1.0 §5.10) and authenticates it. The URI must use
// https for either method unless HTTP is allowed for local tests; redirects
// are not followed.
func (b *requestBuilder) WithRequestObjectURI(uri string, method RequestURIMethod) *requestBuilder {
	if b.errValidation != nil {
		return b
	}
	body, err := b.fetchRequestObjectByReference(uri, method, b.settings().requestURIPost, "application/oauth-authz-req+jwt")
	if err != nil {
		b.errValidation = err
		return b
	}
	return b.withRequestObject(string(body))
}

// AuthorityKeyIdentifiersFromCredential returns the base64url-encoded Authority
// Key Identifiers (RFC 5280 Section 4.2.1.1) of the certificates in the issuer
// JWT header x5c chain of an SD-JWT VC (or JWT VC) wire value. It lets the
// wallet evaluate DCQL aki trusted_authorities queries (OID4VP 1.0 Section
// 6.1.1.1), which HAIP 1.0 section 5 requires.
func AuthorityKeyIdentifiersFromCredential(rawCredential string) []string {
	issuerJWT := rawCredential
	if separator := strings.IndexByte(issuerJWT, '~'); separator >= 0 {
		issuerJWT = issuerJWT[:separator]
	}
	certificates, err := commonX509.DecodeX5CFromJWTHeader(issuerJWT)
	if err != nil {
		return nil
	}
	identifiers := make([]string, 0, len(certificates))
	for _, certificate := range certificates {
		if len(certificate.AuthorityKeyId) == 0 {
			continue
		}
		identifiers = append(identifiers, base64.RawURLEncoding.EncodeToString(certificate.AuthorityKeyId))
	}
	return identifiers
}

// Build returns the admitted request, or the first refusal.
func (b *requestBuilder) Build() (*CredentialPresentationRequest, error) {
	if b.errValidation != nil {
		return nil, b.errValidation
	}
	if err := b.checkPreRegisteredClient(); err != nil {
		return nil, err
	}
	if err := b.validateResponseEncryptionMetadata(); err != nil {
		// The Verifier asked for an encrypted response and left nothing to
		// encrypt it to, so even the refusal is not sent in the clear.
		b.errorResponseAllowed = false
		return nil, err
	}
	if err := b.enforceProfileOptions(); err != nil {
		return nil, err
	}
	if b.req.ClientMetadata != nil {
		b.req.ClientMetadata.admitEncryptionRules(b.options.ResponseEncryption)
	}
	return b.req, nil
}
