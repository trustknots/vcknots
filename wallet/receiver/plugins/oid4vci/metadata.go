package oid4vci

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/trustknots/vcknots/wallet/common"
	commonjose "github.com/trustknots/vcknots/wallet/common/jose"
	"github.com/trustknots/vcknots/wallet/common/observe"
	commonX509 "github.com/trustknots/vcknots/wallet/common/x509"
	"github.com/trustknots/vcknots/wallet/internal/httpfetch"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp/federation"
	"github.com/trustknots/vcknots/wallet/profile"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

const (
	wellKnownCredentialIssuer    = "/.well-known/openid-credential-issuer"
	wellKnownAuthorizationServer = "/.well-known/oauth-authorization-server"
)

// ErrIssuerIdentifierMismatch reports Credential Issuer Metadata whose
// credential_issuer is not the requested Credential Issuer Identifier
// (OpenID4VCI 1.0 Section 12.2.4, compared without normalization).
var ErrIssuerIdentifierMismatch = common.NewCodedError("issuer_metadata_identity_mismatch", "credential_issuer does not match the requested Credential Issuer Identifier")

// ErrAuthorizationServerIssuerMismatch reports that authorization server
// metadata names an issuer other than the identifier it was requested for,
// which RFC 8414 Section 3.3 forbids using.
var ErrAuthorizationServerIssuerMismatch = common.NewCodedError("authorization_server_metadata_issuer_mismatch", "authorization server metadata issuer does not match the requested identifier")

// Sentinel errors of OpenID4VCI 1.0 Section 12.2.3 signed Credential Issuer
// Metadata. They exist so a caller can branch on why a signed document was not
// accepted — with errors.Is, which holds through every wrapping this package
// performs — instead of matching message text.
//
// ErrIssuerMetadataSignatureInvalid is the umbrella every rejection of a signed
// document satisfies; the conditions a caller commonly reports separately wrap
// it in turn, so errors.Is holds for both the specific cause and the umbrella.
// The trust path's own failures additionally arrive as a
// *x509.SigningChainError or *x509.CRLCheckError from wallet/common/x509, which
// carry the certificate and the reason and stay recoverable with errors.As.
var (
	// ErrIssuerMetadataSignatureInvalid reports that the Credential Issuer
	// answered with a signed metadata document the Wallet could not accept:
	// Section 12.2.3 requires the Wallet to "establish trust in the signer of
	// the metadata. Otherwise, the Wallet MUST reject the signed metadata", and
	// every check that establishes that trust — the typ and alg JOSE headers,
	// the x5c chain to a configured anchor, the signature itself, and the
	// registered claims below — reports its failure through this error.
	ErrIssuerMetadataSignatureInvalid = common.NewCodedError("issuer_metadata_signature_invalid", "signed issuer metadata was not accepted")
	// ErrIssuerMetadataSubjectMismatch reports that the sub claim, which
	// Section 12.2.3 defines as "REQUIRED. String matching the Credential
	// Issuer Identifier", names another identifier than the one the metadata
	// was requested from.
	ErrIssuerMetadataSubjectMismatch = common.WrapCoded(
		"issuer_metadata_subject_mismatch",
		"signed issuer metadata sub is not the requested Credential Issuer Identifier",
		ErrIssuerMetadataSignatureInvalid)
	// ErrIssuerMetadataLeafDNSMismatch reports that the signing certificate
	// carries no dNSName Subject Alternative Name equal to the DNS name the
	// signer was required to be bound to. It is reachable only when the caller
	// asks for that binding through IssuerMetadataSigningOptions.
	ErrIssuerMetadataLeafDNSMismatch = common.WrapCoded(
		"issuer_metadata_leaf_dns_mismatch",
		"signed issuer metadata signer is not bound to the expected DNS name",
		ErrIssuerMetadataSignatureInvalid)
	// ErrIssuerMetadataExpired reports that the optional exp claim of Section
	// 12.2.3 is not in the future of the verification clock.
	ErrIssuerMetadataExpired = common.WrapCoded(
		"issuer_metadata_expired",
		"signed issuer metadata has expired",
		ErrIssuerMetadataSignatureInvalid)
	// ErrIssuerMetadataSignatureRequired reports that signed metadata was
	// demanded and none was obtained: the Credential Issuer answered with the
	// unsigned application/json document Section 12.2.2 lets it publish, or the
	// demand was made without the trust material Section 12.2.3 needs to
	// authenticate a signer. It is a policy outcome, not a rejected signature,
	// and therefore does not satisfy ErrIssuerMetadataSignatureInvalid.
	ErrIssuerMetadataSignatureRequired = common.NewCodedError("issuer_metadata_signature_required", "signed issuer metadata is required")
)

// requireMatchingCredentialIssuer enforces the OpenID4VCI 1.0 Section 12.2.4
// identity rule on a decoded Credential Issuer Metadata document: the
// credential_issuer member MUST be the Credential Issuer Identifier the wallet
// requested the document from, compared as a simple string with no
// normalization. A document that names any other identifier is not the
// requested issuer's, whatever it contains, so decoding fails closed before the
// metadata is returned. Both the unsigned application/json document and the
// payload of a signed application/jwt one pass through here.
func requireMatchingCredentialIssuer(declared, identifier string) error {
	if declared != identifier {
		return fmt.Errorf(
			"issuer metadata credential_issuer %q does not match the requested Credential Issuer Identifier %q: %w",
			declared, identifier, ErrIssuerIdentifierMismatch)
	}
	return nil
}

// FetchIssuerMetadata is DiscoverCredentialIssuer bound to
// context.Background(), for the types.Receiver contract.
func (o *Oid4vciReceiver) FetchIssuerMetadata(endpoint common.URIField, receivingTypes types.SupportedReceivingTypes) (*types.CredentialIssuerMetadata, error) {
	if receivingTypes != types.Oid4vci {
		return nil, fmt.Errorf("unsupported serialization flavor")
	}
	return o.DiscoverCredentialIssuer(context.Background(), endpoint)
}

// DiscoverCredentialIssuer resolves the OpenID4VCI 1.0 Section 12.2 Credential
// Issuer Metadata of issuer (a Credential Issuer Identifier, or its well-known
// metadata URL). The document's credential_issuer must equal the identifier
// (Section 12.2.4); signed metadata follows IssuerMetadataSigning (Section
// 12.2.3); under HAIP the metadata must also satisfy HAIP Section 4.1.
func (o *Oid4vciReceiver) DiscoverCredentialIssuer(ctx context.Context, issuer common.URIField) (*types.CredentialIssuerMetadata, error) {
	normalized, err := o.normalizedProfile()
	if err != nil {
		return nil, err
	}
	if err := o.requireHAIPTransport(normalized); err != nil {
		return nil, err
	}
	metadata, err := o.fetchIssuerMetadata(ctx, issuer, normalized)
	if err != nil {
		return nil, stageError(StageIssuerMetadata, fmt.Errorf("failed to fetch issuer metadata: %w", err))
	}
	if err := requireHAIPIssuerMetadata(normalized, metadata); err != nil {
		return nil, err
	}
	return metadata, nil
}

// fetchIssuerMetadata fetches the Section 12.2.2 document. After a 404 it
// tries the Draft 13 location when AppendedMetadataPathFallback allows it, and
// then the issuer's OpenID Federation Entity when IssuerMetadataFederation is
// set.
func (o *Oid4vciReceiver) fetchIssuerMetadata(ctx context.Context, endpoint common.URIField, normalized profile.Profile) (*types.CredentialIssuerMetadata, error) {
	signing := o.issuerMetadataSigningOptions(normalized)
	identifier := credentialIssuerIdentifier(url.URL(endpoint))

	var metadata types.CredentialIssuerMetadata
	err := o.fetchFinalIssuerMetadata(ctx, endpoint, identifier, signing, normalized, &metadata)
	if err == nil {
		return &metadata, nil
	}
	endpointURL := url.URL(endpoint)
	if o.AppendedMetadataPathFallback && !normalized.IsHAIP() && isNotFound(err) &&
		strings.Trim(endpointURL.Path, "/") != "" &&
		!strings.Contains(endpointURL.Path, wellKnownCredentialIssuer) {
		appendedURL := *endpointURL.JoinPath(wellKnownCredentialIssuer)
		if err = o.fetchIssuerMetadataDocument(ctx, appendedURL, identifier, signing, normalized, &metadata); err == nil {
			return &metadata, nil
		}
	}
	if o.IssuerMetadataFederation != nil && !signing.Require && isNotFound(err) {
		return o.federationIssuerMetadata(ctx, identifier)
	}
	return nil, err
}

// isNotFound reports a 404 answer to a metadata request.
func isNotFound(err error) bool {
	var statusError *httpStatusError
	return errors.As(err, &statusError) && statusError.isNotFound()
}

// credentialIssuerEntityType is the OpenID Federation Entity Type whose
// metadata is Credential Issuer Metadata.
const credentialIssuerEntityType = "openid_credential_issuer"

// federationIssuerMetadata derives the Credential Issuer Metadata of
// identifier from the first of its valid Trust Chains that yields it. The
// credential_issuer member must still equal identifier (Section 12.2.4).
func (o *Oid4vciReceiver) federationIssuerMetadata(ctx context.Context, identifier string) (*types.CredentialIssuerMetadata, error) {
	resolver := *o.IssuerMetadataFederation
	if resolver.HTTPClient == nil {
		resolver.HTTPClient = o.HTTPClient
	}
	chains, err := resolver.ResolveTrustChains(ctx, identifier)
	if err != nil {
		return nil, fmt.Errorf("issuer metadata from OpenID Federation: %w", err)
	}
	for _, chain := range chains {
		derived, deriveErr := federation.DeriveEntityMetadata(chain, credentialIssuerEntityType)
		if deriveErr != nil {
			err = deriveErr
			continue
		}
		document, err := json.Marshal(derived)
		if err != nil {
			return nil, fmt.Errorf("issuer metadata from OpenID Federation: %w", err)
		}
		var metadata types.CredentialIssuerMetadata
		if err := json.Unmarshal(document, &metadata); err != nil {
			return nil, fmt.Errorf("issuer metadata from OpenID Federation: failed to parse: %w", err)
		}
		if err := requireMatchingCredentialIssuer(metadata.CredentialIssuer, identifier); err != nil {
			return nil, err
		}
		metadata.RawDocument = document
		return &metadata, nil
	}
	return nil, fmt.Errorf("issuer metadata from OpenID Federation: %w", err)
}

// issuerMetadataSigningOptions resolves the signed metadata policy for one
// fetch. HAIP Section 4.1 requires signed Credential Issuer Metadata to be
// supported "When Ecosystem policies require Issuer Authentication to a higher
// level than possible with TLS alone", which makes the capability mandatory and
// its use conditional: an unconfigured HAIP receiver therefore asks for signed
// metadata but still accepts the unsigned application/json document every
// Credential Issuer MUST publish (Section 12.2.2). A caller that supplies
// options keeps them verbatim, so opting out of the request is possible.
func (o *Oid4vciReceiver) issuerMetadataSigningOptions(normalized profile.Profile) IssuerMetadataSigningOptions {
	if o.IssuerMetadataSigning != nil {
		return *o.IssuerMetadataSigning
	}
	return IssuerMetadataSigningOptions{Request: normalized.IsHAIP()}
}

// credentialIssuerIdentifier recovers the Credential Issuer Identifier from the
// endpoint a fetch was addressed to. Section 12.2.2 forms the metadata URL by
// inserting the well-known path between the host and path components of the
// identifier, so removing that prefix is the inverse; an endpoint that is
// already the identifier is returned unchanged. Query and fragment components
// are dropped because Section 12.2.1 forbids them in an identifier. Nothing
// else is normalised: Section 12.2.4 compares the metadata's credential_issuer
// with this value "using a simple string comparison with no normalization", so
// a trailing slash the issuer chose is part of its identity and is kept.
func credentialIssuerIdentifier(endpointURL url.URL) string {
	identifier := endpointURL
	identifier.RawQuery = ""
	identifier.Fragment = ""
	identifier.ForceQuery = false
	if rest, found := strings.CutPrefix(identifier.Path, wellKnownCredentialIssuer); found {
		identifier.Path = rest
	}
	return identifier.String()
}

func (o *Oid4vciReceiver) fetchFinalIssuerMetadata(ctx context.Context, endpoint common.URIField, identifier string, signing IssuerMetadataSigningOptions, normalized profile.Profile, target *types.CredentialIssuerMetadata) error {
	endpointURL := url.URL(endpoint)
	originalPath := endpointURL.Path
	if originalPath == "/" {
		originalPath = ""
	}
	if !strings.HasPrefix(originalPath, wellKnownCredentialIssuer) {
		endpointURL.Path = wellKnownCredentialIssuer + originalPath
	}
	return o.fetchIssuerMetadataDocument(ctx, endpointURL, identifier, signing, normalized, target)
}

// IssuerMetadataSigningOptions configures OpenID4VCI 1.0 Section 12.2.3 signed
// Credential Issuer Metadata. Section 12.2.2 lets a Credential Issuer answer the
// metadata request with either an unsigned application/json document or a signed
// application/jwt one, and the Wallet signals which it accepts through the
// Accept header; Section 12.2.3 then requires that "When requesting signed
// metadata, the Wallet MUST establish trust in the signer of the metadata.
// Otherwise, the Wallet MUST reject the signed metadata."
type IssuerMetadataSigningOptions struct {
	// Request sends "Accept: application/jwt, application/json;q=0.9". It has no
	// effect unless trust material is configured, because metadata whose signer
	// cannot be authenticated must be rejected rather than requested.
	Request bool
	// Require rejects an unsigned application/json response. It defaults to
	// false in every profile, HAIP included: HAIP Section 4.1 makes signed
	// metadata a capability both sides MUST support, not a step every flow
	// performs. It cannot be satisfied without trust material, so setting it
	// without anchors fails the fetch instead of silently accepting.
	Require bool
	// TrustAnchors and RootCAs carry the signer trust configuration. Supply
	// exactly one of them; RootCAs preserves *x509.CertPool integrations.
	TrustAnchors []*x509.Certificate
	RootCAs      *x509.CertPool
	// KeyUsages constrains the extended key usage of the signing certificate.
	// Empty means no additional EKU policy, not TLS server authentication.
	KeyUsages []x509.ExtKeyUsage
	// AllowUnadvertisedRevocation keeps certificates that advertise no CRL
	// distribution point on the trust path, matching the issuer and Request
	// Object trust policies.
	AllowUnadvertisedRevocation bool
	// CRL tunes the revocation retrieval the trust path performs. Its
	// RequireStatus is derived from AllowUnadvertisedRevocation and must not be
	// set here as well.
	CRL commonX509.CRLCheckerOptions
	// RequireIssuerDNSBinding binds the signer to the Credential Issuer
	// Identifier's host: the leaf certificate MUST carry that host as a
	// dNSName Subject Alternative Name. It is ecosystem policy rather than a
	// Section 12.2.3 requirement — the section establishes trust in the signer
	// through the chain alone — and it is spelled as the credential acceptance
	// policy spells the same rule for an issuer certificate, so an integrator
	// meets one name for it. A Credential Issuer Identifier with no host fails
	// the fetch rather than silently skipping the binding.
	RequireIssuerDNSBinding bool
	// ExpectedLeafDNSName overrides the DNS name the binding matches, for an
	// ecosystem whose signer is named by something other than the identifier's
	// own host. A non-empty value is enforced whether or not
	// RequireIssuerDNSBinding is set. The match is the exact, case-insensitive
	// one commonX509.RequireLeafDNSName performs for every identifier in this
	// library: a wildcard SAN authenticates a TLS server, not the Credential
	// Issuer the metadata speaks for.
	ExpectedLeafDNSName string
	// Now supplies the verification time, for tests and for callers with their
	// own clock. Nil means time.Now.
	Now func() time.Time
}

// expectedLeafDNSName resolves the dNSName SAN the signing certificate must
// carry for one fetch, or "" when the caller asked for no binding. identifier
// is the Credential Issuer Identifier the metadata was requested from.
func (s IssuerMetadataSigningOptions) expectedLeafDNSName(identifier string) (string, error) {
	if name := strings.TrimSpace(s.ExpectedLeafDNSName); name != "" {
		return name, nil
	}
	if !s.RequireIssuerDNSBinding {
		return "", nil
	}
	parsed, err := url.Parse(identifier)
	if err != nil || parsed.Hostname() == "" {
		return "", fmt.Errorf(
			"%w: the Credential Issuer Identifier %q names no host to bind the signer to",
			ErrIssuerMetadataLeafDNSMismatch, identifier)
	}
	return parsed.Hostname(), nil
}

// signedIssuerMetadataJWTType is the media type Section 12.2.3 requires in the
// typ JOSE header of signed Credential Issuer Metadata.
const signedIssuerMetadataJWTType = "openidvci-issuer-metadata+jwt"

// fetchIssuerMetadataDocument performs one Credential Issuer Metadata request
// and decodes the response by its media type, per Section 12.2.2. identifier is
// the Credential Issuer Identifier the request was derived from; signed metadata
// is bound to it through the sub claim.
func (o *Oid4vciReceiver) fetchIssuerMetadataDocument(ctx context.Context, requestURL url.URL, identifier string, signing IssuerMetadataSigningOptions, normalized profile.Profile, target *types.CredentialIssuerMetadata) error {
	trustConfigured := len(signing.TrustAnchors) > 0 || signing.RootCAs != nil
	if signing.Require && !trustConfigured {
		return fmt.Errorf("%w: no trust anchors are configured", ErrIssuerMetadataSignatureRequired)
	}

	// Section 12.2.2: the Wallet is RECOMMENDED to send an Accept header
	// "to indicate the Content Type(s) it supports, and by doing so, signaling
	// whether it supports signed metadata". Asking for a signed document the
	// wallet could not authenticate would only invite a response it must reject.
	accept := "application/json"
	if signing.Request && trustConfigured {
		accept = "application/jwt, application/json;q=0.9"
	}
	response, err := o.do(observe.WithEndpoint(ctx, observe.EndpointIssuerMetadata), exchange{
		method: http.MethodGet,
		url:    requestURL,
		accept: accept,
	})
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	if response.statusCode != http.StatusOK {
		return response.statusError()
	}
	bodyBytes := response.body
	if len(bodyBytes) == 0 {
		return fmt.Errorf("empty response body")
	}

	if httpfetch.MediaTypeIs(response.header, "application/jwt") {
		return o.decodeSignedIssuerMetadata(ctx, strings.TrimSpace(string(bodyBytes)), identifier, signing, normalized, target)
	}
	if signing.Require {
		return fmt.Errorf("%w: the Credential Issuer answered with an unsigned document",
			ErrIssuerMetadataSignatureRequired)
	}
	if err := json.Unmarshal(bodyBytes, target); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}
	if err := requireMatchingCredentialIssuer(target.CredentialIssuer, identifier); err != nil {
		return err
	}
	// Section 12.2.2 allows metadata members this library does not model, and a
	// Credential Issuer may publish extensions of its own. The accepted bytes
	// are kept so a caller reads the document the issuer published rather than
	// a re-serialization of the parsed struct.
	target.RawDocument = bytes.Clone(bodyBytes)
	return nil
}

// decodeSignedIssuerMetadata verifies a signed metadata JWT and takes its
// payload as the metadata. Section 12.2.3 requires that "All metadata parameters
// used by the Credential Issuer MUST be added as top-level claims in the JWS
// payload", so the verified payload is the complete document and nothing is
// merged from an unsigned one.
func (o *Oid4vciReceiver) decodeSignedIssuerMetadata(ctx context.Context, compact string, identifier string, signing IssuerMetadataSigningOptions, normalized profile.Profile, target *types.CredentialIssuerMetadata) error {
	verification, payload, err := o.verifySignedIssuerMetadata(ctx, compact, identifier, signing, normalized)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(payload, target); err != nil {
		return fmt.Errorf("failed to parse signed issuer metadata payload: %w", err)
	}
	// Section 12.2.4 binds the credential_issuer member of the payload to the
	// requested identifier just as Section 12.2.3 binds the sub claim, so a
	// signed document is rejected on either mismatch.
	if err := requireMatchingCredentialIssuer(target.CredentialIssuer, identifier); err != nil {
		return err
	}
	target.SignedMetadata = compact
	target.MetadataSignature = verification
	// The verified payload is the complete document, including the members this
	// library does not model, so it is the document the caller reads.
	target.RawDocument = bytes.Clone(payload)
	return nil
}

// verifySignedIssuerMetadata authenticates the signer of a signed Credential
// Issuer Metadata JWT and returns the verified payload. Key resolution is the
// x5c JOSE header, which HAIP Section 4.1 requires: "Key resolution for the
// signed Credential Issuer Metadata MUST be supported using the `x5c` JOSE
// header parameter"; the same section forbids the trust anchor inside x5c and a
// self-signed signing certificate.
func (o *Oid4vciReceiver) verifySignedIssuerMetadata(ctx context.Context, compact string, identifier string, signing IssuerMetadataSigningOptions, normalized profile.Profile) (*types.MetadataVerification, []byte, error) {
	if len(signing.TrustAnchors) == 0 && signing.RootCAs == nil {
		return nil, nil, fmt.Errorf("%w: no trust anchors are configured", ErrIssuerMetadataSignatureInvalid)
	}
	expectedDNSName, err := signing.expectedLeafDNSName(identifier)
	if err != nil {
		return nil, nil, err
	}
	// Section 12.2.3: alg is a digital signature algorithm and "MUST NOT be
	// `none` or an identifier for a symmetric algorithm (MAC)", which the
	// accepted set never includes.
	signed, err := jose.ParseSigned(compact, commonjose.AcceptedSignatureAlgorithms())
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrIssuerMetadataSignatureInvalid, err)
	}
	if len(signed.Signatures) != 1 {
		return nil, nil, fmt.Errorf("%w: signed issuer metadata must carry exactly one signature",
			ErrIssuerMetadataSignatureInvalid)
	}
	typ, _ := signed.Signatures[0].Header.ExtraHeaders[jose.HeaderType].(string)
	if typ != signedIssuerMetadataJWTType {
		return nil, nil, fmt.Errorf("%w: typ must be %q, got %q",
			ErrIssuerMetadataSignatureInvalid, signedIssuerMetadataJWTType, typ)
	}

	chain, err := commonX509.DecodeX5CFromJWTHeader(compact)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrIssuerMetadataSignatureInvalid, err)
	}
	if normalized.IsHAIP() {
		containsAnchor, err := commonX509.ContainsTrustAnchor(chain, signing.TrustAnchors, signing.RootCAs)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %w", ErrIssuerMetadataSignatureInvalid, err)
		}
		if containsAnchor {
			return nil, nil, fmt.Errorf(
				"%w: HAIP forbids including the trust anchor certificate in the x5c header",
				ErrIssuerMetadataSignatureInvalid)
		}
		if err := commonX509.RequireNonSelfSignedLeaf(chain, "signed issuer metadata"); err != nil {
			return nil, nil, fmt.Errorf("%w: %w", ErrIssuerMetadataSignatureInvalid, err)
		}
	}

	now := time.Now()
	if signing.Now != nil {
		now = signing.Now()
	}
	result, err := commonX509.VerifySigningChainWithPolicy(ctx, chain, commonX509.SigningChainPolicy{
		TrustAnchors:                signing.TrustAnchors,
		Roots:                       signing.RootCAs,
		KeyUsages:                   signing.KeyUsages,
		CRL:                         signing.CRL,
		AllowUnadvertisedRevocation: signing.AllowUnadvertisedRevocation,
		CurrentTime:                 now,
		HTTPClient:                  httpfetch.NoRedirect(o.HTTPClient),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrIssuerMetadataSignatureInvalid, err)
	}
	// The chain authenticates the signer against the configured anchors;
	// binding it to a DNS name is what names which Credential Issuer that
	// signer is allowed to speak for, so it is applied to the verified leaf.
	if expectedDNSName != "" {
		if err := commonX509.RequireLeafDNSName(result.Chain[0], expectedDNSName, false); err != nil {
			return nil, nil, fmt.Errorf("%w: the leaf certificate carries no dNSName SAN %q: %w",
				ErrIssuerMetadataLeafDNSMismatch, expectedDNSName, err)
		}
	}

	payload, err := signed.Verify(result.Chain[0].PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrIssuerMetadataSignatureInvalid, err)
	}

	var claims struct {
		Sub string `json:"sub"`
		Iat *int64 `json:"iat"`
		Exp *int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, nil, fmt.Errorf("%w: failed to parse the payload: %w",
			ErrIssuerMetadataSignatureInvalid, err)
	}
	// Section 12.2.3: sub is "REQUIRED. String matching the Credential Issuer
	// Identifier". Binding it to the identifier the metadata was requested from
	// is what stops one issuer's signed document from standing in for another's.
	//
	// The comparison is exact. Section 12.2.4 states the rule for the identity
	// of a Credential Issuer: "The value MUST be identical to the Credential
	// Issuer's identifier value into which the well-known URI string was
	// inserted to create the URL used to retrieve the metadata. If these values
	// are not identical (when compared using a simple string comparison with no
	// normalization), the data contained in the response MUST NOT be used." A
	// wallet that trimmed a trailing slash first would be normalizing, and would
	// accept a document signed for a different identifier than the one it asked.
	if claims.Sub != identifier {
		return nil, nil, fmt.Errorf("%w: sub %q does not match the credential issuer %q",
			ErrIssuerMetadataSubjectMismatch, claims.Sub, identifier)
	}
	if claims.Iat == nil {
		return nil, nil, fmt.Errorf("%w: the required iat claim is missing",
			ErrIssuerMetadataSignatureInvalid)
	}
	verification := &types.MetadataVerification{
		LeafCertificateSHA256: result.Fingerprints[0],
		CertificateSHA256:     slices.Clone(result.Fingerprints),
		Subject:               result.Chain[0].Subject.String(),
		IssuedAt:              time.Unix(*claims.Iat, 0).UTC(),
	}
	// The verified path is leaf first and ends at the configured anchor it
	// reached, so its last fingerprint names the anchor the metadata was
	// accepted under.
	if len(result.Fingerprints) > 1 {
		verification.AnchorSHA256 = result.Fingerprints[len(result.Fingerprints)-1]
	}
	if claims.Exp != nil {
		expiresAt := time.Unix(*claims.Exp, 0).UTC()
		if !expiresAt.After(now) {
			return nil, nil, fmt.Errorf("%w: exp was %s",
				ErrIssuerMetadataExpired, expiresAt.Format(time.RFC3339))
		}
		verification.ExpiresAt = &expiresAt
	}
	return verification, payload, nil
}

// FetchAuthorizationServerMetadata is DiscoverAuthorizationServer bound to
// context.Background(), for the types.Receiver contract.
func (o *Oid4vciReceiver) FetchAuthorizationServerMetadata(endpoint common.URIField, receivingTypes types.SupportedReceivingTypes) (*types.AuthorizationServerMetadata, error) {
	if receivingTypes != types.Oid4vci {
		return nil, fmt.Errorf("unsupported flavor: %v", receivingTypes)
	}
	return o.DiscoverAuthorizationServer(context.Background(), endpoint)
}

// DiscoverAuthorizationServer resolves the RFC 8414 metadata of the
// authorization server issuer (its identifier, or its well-known metadata
// URL) and refuses a document whose issuer is not that identifier (RFC 8414
// Section 3.3, compared exactly).
func (o *Oid4vciReceiver) DiscoverAuthorizationServer(ctx context.Context, issuer common.URIField) (*types.AuthorizationServerMetadata, error) {
	normalized, err := o.normalizedProfile()
	if err != nil {
		return nil, err
	}
	if err := o.requireHAIPTransport(normalized); err != nil {
		return nil, err
	}

	var metadata types.AuthorizationServerMetadata
	if err := o.fetchMetadataDocument(observe.WithEndpoint(ctx, observe.EndpointAuthorizationServerMetadata), authorizationServerMetadataURL(url.URL(issuer)), &metadata); err != nil {
		return nil, stageError(StageAuthorizationServerMetadata, fmt.Errorf("failed to fetch authorization server metadata: %w", err))
	}
	if identifier := authorizationServerIdentifier(url.URL(issuer)); metadata.Issuer.String() != identifier {
		return nil, stageError(StageAuthorizationServerMetadata, fmt.Errorf(
			"authorization server metadata issuer %q is not the requested identifier %q: %w",
			metadata.Issuer.String(), identifier, ErrAuthorizationServerIssuerMismatch))
	}
	return &metadata, nil
}

// authorizationServerIdentifier is the issuer identifier endpoint names: the
// endpoint itself, or, for an endpoint that already is the RFC 8414 Section
// 3.1 well-known URL, the URL with the well-known path removed.
func authorizationServerIdentifier(endpointURL url.URL) string {
	if rest, found := strings.CutPrefix(endpointURL.Path, wellKnownAuthorizationServer); found {
		endpointURL.Path = rest
		endpointURL.RawPath = ""
	}
	return endpointURL.String()
}

// authorizationServerMetadataURL inserts the RFC 8414 Section 3.1 well-known
// path between the host and the path of an authorization server identifier,
// after removing a terminating "/" from the path. An endpoint that already
// names the well-known document is returned unchanged.
func authorizationServerMetadataURL(endpointURL url.URL) url.URL {
	path := strings.TrimSuffix(endpointURL.Path, "/")
	if !strings.HasPrefix(path, wellKnownAuthorizationServer) {
		endpointURL.Path = wellKnownAuthorizationServer + path
		endpointURL.RawPath = ""
	}
	return endpointURL
}

// fetchMetadataDocument GETs a JSON metadata document, which RFC 8414 Section
// 3.2 serves with 200 OK.
func (o *Oid4vciReceiver) fetchMetadataDocument(ctx context.Context, requestURL url.URL, target any) error {
	response, err := o.do(ctx, exchange{method: http.MethodGet, url: requestURL})
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	if response.statusCode != http.StatusOK {
		return response.statusError()
	}
	if len(response.body) == 0 {
		return fmt.Errorf("empty response body")
	}
	if err := json.Unmarshal(response.body, target); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}
	return nil
}

// ValidateCredentialConfigurationForProfile applies the HAIP 1.0 constraints on
// a single Credential Configuration. Under Final every configuration is
// accepted. HAIP §4.1: "The Credential Issuer metadata MUST include a scope for
// every Credential Configuration it supports"; HAIP §5.3.2 and §6 restrict the
// offered credential formats to SD-JWT VC (dc+sd-jwt) and ISO mdoc (mso_mdoc).
func (o *Oid4vciReceiver) ValidateCredentialConfigurationForProfile(config types.CredentialConfiguration) error {
	normalized, err := o.normalizedProfile()
	if err != nil {
		return err
	}
	if !normalized.IsHAIP() {
		return nil
	}
	if strings.TrimSpace(config.Scope) == "" {
		return fmt.Errorf("HAIP requires a scope for every credential configuration")
	}
	switch strings.ToLower(strings.TrimSpace(config.Format)) {
	case "dc+sd-jwt", "mso_mdoc":
		return nil
	default:
		return fmt.Errorf("HAIP requires credential format dc+sd-jwt or mso_mdoc, got %q", config.Format)
	}
}

// requireHAIPIssuerMetadata applies HAIP Section 4.1: a nonce_endpoint is
// required when a Credential Configuration advertises
// cryptographic_binding_methods_supported.
func requireHAIPIssuerMetadata(normalized profile.Profile, metadata *types.CredentialIssuerMetadata) error {
	if !normalized.IsHAIP() || metadata.NonceEndpoint != nil {
		return nil
	}
	for id, config := range metadata.CredentialConfigurationSupported {
		if config.CryptographicBindingMethodsSupported != nil && len(*config.CryptographicBindingMethodsSupported) > 0 {
			return fmt.Errorf("HAIP requires nonce_endpoint when credential configuration %q advertises cryptographic_binding_methods_supported", id)
		}
	}
	return nil
}
