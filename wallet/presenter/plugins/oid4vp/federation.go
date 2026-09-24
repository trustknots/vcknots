package oid4vp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	commonJOSE "github.com/trustknots/vcknots/wallet/common/jose"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp/federation"
)

// FederationTrustOptions is the relying-party configuration the
// openid_federation Client Identifier Prefix is authenticated against. It is
// never populated from the request being authenticated: the Trust Anchors a
// Wallet accepts are its own decision, and OpenID4VP 1.0 Section 5.9.3 requires
// the final Verifier metadata to come "from the Trust Chain after applying the
// policies" rather than from anything the Verifier asserts about itself.
type FederationTrustOptions struct {
	// TrustAnchors are the Federation Entities this Wallet trusts. A Request
	// Object whose Trust Chain reaches none of them is refused.
	TrustAnchors []federation.TrustAnchor
	// HTTPClient performs the Entity Statement retrievals of one resolution.
	// A nil value uses the presenter's client.
	HTTPClient *http.Client
	// MaxDepth bounds the Trust Chain discovery. Zero means the package
	// default.
	MaxDepth int
	// MaxStatementBytes bounds one Entity Statement response. Zero means the
	// package default.
	MaxStatementBytes int64
	// RequirePublicNetworkHost refuses an Entity Statement URL whose host is
	// not reachable on the public network, so a Trust Chain cannot be used to
	// reach a Wallet-internal address.
	RequirePublicNetworkHost bool
	// IsPublicNetworkHost decides that question. A nil value with
	// RequirePublicNetworkHost set refuses every host.
	IsPublicNetworkHost func(host string) bool
	// PreferredLocales orders the language-tagged federation_entity metadata a
	// Wallet displays. Empty means English.
	PreferredLocales []string
	// SigningAlgorithms bounds the Request Object signature algorithms of a
	// federation Verifier. Empty means DefaultFederationRequestObjectAlgorithms().
	SigningAlgorithms []jose.SignatureAlgorithm
	// AllowUnsignedRequests accepts an openid_federation request in plain
	// parameters when its response endpoint is one of the redirect_uris the
	// Trust Chain registers. OpenID Federation authenticates a Relying Party
	// by its signed Request Object, so the zero value refuses unsigned
	// requests with ErrRequestObjectSignatureRequired before resolving any
	// Trust Chain.
	AllowUnsignedRequests bool
}

// DefaultFederationRequestObjectAlgorithms returns a copy of the Request
// Object signature policy applied when FederationTrustOptions leaves
// SigningAlgorithms empty: ES256 alone, the algorithm every OpenID Federation
// deployment interoperates on. A deployment that accepts more says so in its
// options.
func DefaultFederationRequestObjectAlgorithms() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{jose.ES256}
}

// FederationEvidence records the Trust Chain that authenticated a Verifier.
// No request parameter can populate it: every value is read from statements
// whose signatures this library verified up to a configured Trust Anchor.
type FederationEvidence struct {
	// SubjectEntityID is the Verifier's Entity Identifier, which is the
	// original Client Identifier of the openid_federation prefix.
	SubjectEntityID string
	// TrustAnchorEntityID is the configured anchor the chain reached.
	TrustAnchorEntityID string
	// TrustPathEntityIDs are the Entity Identifiers of the chain, subject
	// first and Trust Anchor last.
	TrustPathEntityIDs []string
	// ExpiresAt is the earliest exp of the chain, in UTC.
	ExpiresAt time.Time
	// StatementCount is the number of Entity Statements in the chain.
	StatementCount int
	// OrganizationName, LogoURI, PolicyURI and HomepageURI are the
	// federation_entity metadata a Wallet shows about the Verifier, selected
	// for the configured locales. Each is empty when the chain carries none.
	OrganizationName string
	LogoURI          string
	PolicyURI        string
	HomepageURI      string
	// Metadata is the final openid_credential_verifier metadata obtained from
	// the Trust Chain after applying the metadata policies.
	Metadata map[string]any
}

// authenticateFederationRequestObject implements the openid_federation Client
// Identifier Prefix of OpenID4VP 1.0 Section 5.9.3: "the original Client
// Identifier ... is an Entity Identifier defined in OpenID Federation.
// Processing rules given in OpenID Federation MUST be followed. The
// Authorization Request MAY also contain a `trust_chain` parameter. The final
// Verifier metadata is obtained from the Trust Chain after applying the
// policies ... The `client_metadata` parameter, if present in the Authorization
// Request, MUST be ignored when this Client Identifier Prefix is used."
func (b *requestCore) authenticateFederationRequestObject(
	obj string,
	parsed *jwt.JSONWebToken,
	clientID *OID4VPClientID,
	options RequestObjectValidationOptions,
) error {
	if options.Federation == nil || len(options.Federation.TrustAnchors) == 0 {
		return fmt.Errorf("%w: no OpenID Federation trust anchor is configured", federation.ErrTrustAnchorNotConfigured)
	}
	header := parsed.Headers[0]
	// OpenID Federation identifies the signing key of an entity by kid within
	// the entity's own JWKS, so a Request Object that names no key cannot be
	// attributed to one of the keys the Trust Chain published.
	if header.KeyID == "" {
		return fmt.Errorf("openid_federation request object must name its signing key in kid: %w", ErrRequestObjectSignatureInvalid)
	}
	algorithms := options.Federation.SigningAlgorithms
	if len(algorithms) == 0 {
		algorithms = DefaultFederationRequestObjectAlgorithms()
	}
	if !slices.Contains(algorithms, jose.SignatureAlgorithm(header.Algorithm)) {
		return fmt.Errorf("openid_federation request object alg %q is not accepted: %w", header.Algorithm, ErrRequestObjectSignatureInvalid)
	}

	carried, err := federationTrustChainFromRequestObject(parsed)
	if err != nil {
		return err
	}
	resolver := b.federationResolver(options)
	trust, err := resolver.ResolveVerifierTrust(
		b.context(),
		clientID.original,
		carried,
		options.Federation.PreferredLocales,
	)
	if err != nil {
		return err
	}

	verified, err := verifyRequestObjectWithKeySet(parsed, trust.RequestObjectJWKS)
	if err != nil {
		return err
	}
	if err := b.requireWalletNonceEcho(verified); err != nil {
		return err
	}
	now := requestObjectNow(options)
	if err := validateRequestObjectClaims(verified, b.resolveClaimPolicy(options, now)); err != nil {
		return fmt.Errorf("JWT standard claims validation failed: %w", err)
	}
	// The response endpoint the Verifier names must be one the federation
	// metadata registered for it, which is the only statement about the
	// Verifier's endpoints that the Trust Chain authenticates.
	if err := federation.AssertResponseURIAllowed(trust.Metadata, b.req.responseEndpoint()); err != nil {
		return err
	}
	if err := b.adoptFederationVerifierMetadata(trust.Metadata); err != nil {
		return err
	}

	evidence := newFederationEvidence(trust)
	b.req.VerifierFederation = evidence
	b.req.RequestObjectVerification = &RequestObjectVerification{
		ClientID:    b.req.ClientID,
		WalletNonce: b.sentWalletNonce,
		ExpiresAt:   requestObjectExpiry(verified),
		Federation:  evidence,
	}
	return nil
}

// newFederationEvidence records what a Trust Chain resolution established
// about a Verifier, for both the signed and the unsigned openid_federation
// request.
func newFederationEvidence(trust *federation.VerifierTrust) *FederationEvidence {
	return &FederationEvidence{
		SubjectEntityID:     trust.TrustChain.SubjectEntityID,
		TrustAnchorEntityID: trust.TrustChain.TrustAnchorEntityID,
		TrustPathEntityIDs:  federation.TrustPathEntityIDs(trust.TrustChain),
		ExpiresAt:           trust.TrustChain.ExpiresAt.UTC(),
		StatementCount:      len(trust.TrustChain.Statements),
		OrganizationName:    trust.OrganizationName,
		LogoURI:             trust.LogoURI,
		PolicyURI:           trust.PolicyURI,
		HomepageURI:         trust.HomepageURI,
		Metadata:            trust.Metadata,
	}
}

// federationResolver builds the Trust Chain resolver one authentication run
// uses, so the transport, the anchors and the time policy of a federation
// resolution are the ones the caller configured for this parse.
func (b *requestCore) federationResolver(options RequestObjectValidationOptions) *federation.Resolver {
	return newFederationResolver(options, b.httpClient)
}

// newFederationResolver builds a resolver from options.Federation, which must
// be set. Its HTTPClient wins over fallback.
func newFederationResolver(options RequestObjectValidationOptions, fallback *http.Client) *federation.Resolver {
	client := options.Federation.HTTPClient
	if client == nil {
		client = fallback
		if client == nil {
			client = (&Oid4vpPresenter{}).httpClient()
		}
	}
	return &federation.Resolver{
		HTTPClient:               client,
		TrustAnchors:             options.Federation.TrustAnchors,
		Now:                      options.Now,
		MaxDepth:                 options.Federation.MaxDepth,
		MaxStatementBytes:        options.Federation.MaxStatementBytes,
		RequirePublicNetworkHost: options.Federation.RequirePublicNetworkHost,
		IsPublicNetworkHost:      options.Federation.IsPublicNetworkHost,
	}
}

// federationTrustChainFromRequestObject reads the Trust Chain a Verifier
// supplied with its request. OpenID Federation carries it in the `trust_chain`
// JOSE header of the signed Request Object; OpenID4VP 1.0 Section 5.9.3 also
// allows the Authorization Request to carry a `trust_chain` parameter, which
// for a signed request is a claim of the Request Object itself. The header wins
// when both are present. A nil result means the chain is to be discovered.
//
// Reading the value before the signature is verified is safe: a supplied chain
// is not evidence until every statement in it has been verified up to a
// configured Trust Anchor, and a chain that does not reach one is refused.
func federationTrustChainFromRequestObject(parsed *jwt.JSONWebToken) ([]string, error) {
	if raw, present := parsed.Headers[0].ExtraHeaders["trust_chain"]; present && raw != nil {
		return federation.ParseTrustChainParameter(raw)
	}
	claims := make(commonJOSE.Claims)
	if err := parsed.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, fmt.Errorf("failed to decode request object claims: %w", err)
	}
	raw, present := claims["trust_chain"]
	if !present || raw == nil {
		return nil, nil
	}
	return federation.ParseTrustChainParameter(raw)
}

// verifyRequestObjectWithKeySet verifies the Request Object against a key set
// the Wallet already trusts for this Verifier. The kid narrows the candidates;
// when it names no key in the set every key is still tried, so a key rotated
// without a new identifier is not refused for that alone.
func verifyRequestObjectWithKeySet(parsed *jwt.JSONWebToken, jwks jose.JSONWebKeySet) (commonJOSE.Claims, error) {
	candidates := jwks.Keys
	if keyID := parsed.Headers[0].KeyID; keyID != "" {
		if narrowed := jwks.Key(keyID); len(narrowed) != 0 {
			candidates = narrowed
		}
	}
	for i := range candidates {
		claims := make(commonJOSE.Claims)
		if err := parsed.Claims(candidates[i], &claims); err == nil {
			return claims, nil
		}
	}
	return nil, fmt.Errorf("request object signature does not verify with any trusted key of the verifier: %w", ErrRequestObjectSignatureInvalid)
}

// adoptFederationVerifierMetadata replaces whatever client_metadata the request
// carried with the metadata the Trust Chain produced, which OpenID4VP 1.0
// Section 5.9.3 makes the only Verifier metadata this Client Identifier Prefix
// has: "The `client_metadata` parameter, if present in the Authorization
// Request, MUST be ignored when this Client Identifier Prefix is used."
func (b *requestCore) adoptFederationVerifierMetadata(metadata map[string]any) error {
	encoded, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("%w: verifier metadata is not serializable: %w", federation.ErrMetadataDerivationFailed, err)
	}
	var verifierMetadata VerifierMetadata
	if err := json.Unmarshal(encoded, &verifierMetadata); err != nil {
		return fmt.Errorf("%w: verifier metadata is not OpenID4VP verifier metadata: %w", federation.ErrMetadataDerivationFailed, err)
	}
	b.req.ClientMetadata = &verifierMetadata
	return nil
}
