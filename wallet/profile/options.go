package profile

import "strings"

// Options are the constraints a profile adds to OpenID4VCI 1.0 and OpenID4VP
// 1.0. Each field is one requirement of HAIP 1.0, named by the section that
// states it, or a check the specifications leave to the Wallet, which no
// profile turns on by default; each can be applied on its own through
// Profile.With. The zero value adds no constraint: it is OpenID4VCI 1.0 /
// OpenID4VP 1.0 Final.
//
// Options is comparable, so a Profile is comparable too. Options.String names
// the options that are on, in the spelling the text form of a Profile and
// OptionError use.
type Options struct {
	// ForbidExperimental refuses every departure of package experimental
	// wherever it is carried: Config.Experimental (Transport and Hooks), the
	// Experimental field of the OpenID4VCI receiver, of the issuer key
	// resolver (through the credential acceptor and the Status List key hook)
	// and of the Status List checker, and every field of the OpenID4VP
	// presenter's Experimental.
	// HAIP 1.0 §4 (FAPI 2.0 TLS), §5 (x509_hash Verifier authentication) and
	// OpenID4VCI 1.0 / OpenID4VP 1.0 as written.
	ForbidExperimental bool
	// ForbidDraftProfiles refuses a wallet whose Config.Profiles enables a
	// draft profile (Draft13, Draft24) beside this one.
	// HAIP 1.0 §1: OpenID4VCI 1.0 and OpenID4VP 1.0 are the base protocols.
	ForbidDraftProfiles bool
	// AllowedCredentialFormats restricts the Credential Format Identifiers a
	// Credential Configuration (OpenID4VCI) or a DCQL Credential Query
	// (OpenID4VP) may use. The zero value restricts nothing.
	// HAIP 1.0 §3, §4 and §5: SD-JWT VC (dc+sd-jwt) or ISO mdoc (mso_mdoc).
	AllowedCredentialFormats CredentialFormats
	// IssuerX5C applies to the issuer signature of an SD-JWT VC being
	// accepted: Require makes a validated x5c chain the only way to
	// authenticate the issuer, ExcludeAnchor refuses a chain carrying a trust
	// anchor, RejectSelfSigned a self-signed leaf.
	// HAIP 1.0 §6.1.1 (Issuer identification and key resolution).
	IssuerX5C X5CRules
	// StatusListTokenX5C applies to the signature of a Status List Token,
	// through statuslist.Checker.Profile: Require makes the x5c leaf key the
	// only verifying key, RejectSelfSigned refuses a self-signed leaf, and
	// ExcludeAnchor (enforced by the key resolution hook, which holds the
	// anchors) a chain carrying a trust anchor.
	// HAIP 1.0 §6.1 (IETF SD-JWT VC Profile).
	StatusListTokenX5C X5CRules
	// RequireStatusListSignerBinding binds the x5c leaf of a Status List
	// Token to the Referenced Token's issuer, beyond the chain reaching a
	// configured trust anchor: the leaf has the key or the non-empty subject
	// of the credential's issuer certificate, shares its issuing certificate
	// authority (issuer name and authority key identifier), or names the host
	// of the credential's https iss. draft-ietf-oauth-status-list-21 §11.3
	// "does not mandate specific methods for key resolution and trust
	// management" and only recommends these links, and HAIP 1.0 §6.1 adds
	// none, so no profile turns it on; HAIPOptions leaves it off.
	RequireStatusListSignerBinding bool

	// RequirePAR refuses an authorization server without a Pushed
	// Authorization Request endpoint.
	// HAIP 1.0 §4 (FAPI 2.0 PAR).
	RequirePAR bool
	// RequireDPoP requires a DPoP key and DPoP-bound access tokens.
	// HAIP 1.0 §4 (sender-constrained access tokens, RFC 9449).
	RequireDPoP bool
	// RequireAuthorizationResponseIss requires the iss parameter in the
	// Authorization Response, advertised or not.
	// HAIP 1.0 §4 (FAPI 2.0, RFC 9207).
	RequireAuthorizationResponseIss bool
	// RequireScopeAuthorization requests the credential by scope only, never
	// by authorization_details.
	// HAIP 1.0 §4.2 (Credential Offer) and §4.3 (Authorization Endpoint).
	RequireScopeAuthorization bool
	// RequireIssuerMetadataScopes refuses a Credential Configuration without
	// a scope.
	// HAIP 1.0 §4.1 (Issuer Metadata).
	RequireIssuerMetadataScopes bool
	// RequireNonceEndpointForKeyBinding refuses Credential Issuer Metadata
	// that advertises cryptographic_binding_methods_supported, or a request
	// with a key attestation, without a nonce_endpoint.
	// HAIP 1.0 §4.1 (Issuer Metadata).
	RequireNonceEndpointForKeyBinding bool
	// RequestSignedIssuerMetadata asks for signed Credential Issuer Metadata
	// when the receiver configures no IssuerMetadataSigning of its own.
	// HAIP 1.0 §4.1 (signed Issuer Metadata MUST be supported).
	RequestSignedIssuerMetadata bool
	// SignedMetadataX5C applies to the x5c header of signed Credential Issuer
	// Metadata. The signer is always resolved from x5c; ExcludeAnchor and
	// RejectSelfSigned add the HAIP certificate rules.
	// HAIP 1.0 §4.1 (Issuer Metadata).
	SignedMetadataX5C X5CRules
	// RequireClientAuthentication requires an OAuth 2.0 client
	// authentication mechanism (Wallet Attestation or private_key_jwt) at the
	// PAR and token endpoints, and a client_id on a pre-authorized_code
	// token request.
	// HAIP 1.0 §4.4.1 (Wallet Attestation).
	RequireClientAuthentication bool
	// AttestationX5C applies to Wallet Attestations and key attestations
	// (OpenID4VCI 1.0 Appendices E and D). It is added to the rules of
	// Config.Attestation.Trust.
	// HAIP 1.0 §4.4.1 (Wallet Attestation) and §4.5.1 (Key Attestation).
	AttestationX5C X5CRules

	// RequireSignedRequestByReference requires a redirect-based
	// Authorization Request to be a signed Request Object the presenter
	// fetched from request_uri itself; a Request Object passed by value is
	// refused.
	// HAIP 1.0 §5.1 (OpenID4VP via redirects).
	RequireSignedRequestByReference bool
	// RequireDirectPostJWT requires the response mode direct_post.jwt on a
	// redirect-based request.
	// HAIP 1.0 §5.1 (OpenID4VP via redirects).
	RequireDirectPostJWT bool
	// RequireDCAPIJWT requires the response mode dc_api.jwt on a Digital
	// Credentials API request.
	// HAIP 1.0 §5.2 (OpenID4VP via the W3C Digital Credentials API).
	RequireDCAPIJWT bool
	// AllowedClientIDPrefixes restricts the Client Identifier Prefix of every
	// request that names a Verifier, which is every request except an
	// unsigned Digital Credentials API one. The zero value restricts nothing.
	// HAIP 1.0 §5 (x509_hash for signed requests).
	AllowedClientIDPrefixes ClientIDPrefixes
	// RequestObjectX5C applies to a signed Request Object: Require accepts
	// only an x509_san_dns or x509_hash Client Identifier, whose Request
	// Object carries x5c; ExcludeAnchor and RejectSelfSigned add the HAIP
	// certificate rules.
	// HAIP 1.0 §5 (signed requests).
	RequestObjectX5C X5CRules
	// ResponseEncryption restricts the encryption of an Authorization
	// Response.
	// HAIP 1.0 §5 (response encryption per OpenID4VP 1.0 §8.3).
	ResponseEncryption ResponseEncryptionRules
	// AlwaysKeyBindingWhenConfirmed presents an SD-JWT VC that carries a cnf
	// claim with a KB-JWT, even when the Verifier did not require holder
	// binding.
	// HAIP 1.0 §6.1.1.1 (Cryptographic Holder Binding between VC and VP).
	AlwaysKeyBindingWhenConfirmed bool
}

// HAIPOptions returns every constraint HAIP 1.0 adds to OpenID4VCI 1.0 and
// OpenID4VP 1.0: all options HAIP states on, credential formats restricted to
// dc+sd-jwt and mso_mdoc, and signed requests to the x509_hash Client
// Identifier Prefix. The checks HAIP leaves to the Wallet
// (RequireStatusListSignerBinding) stay off.
func HAIPOptions() Options {
	all := X5CRules{Require: true, ExcludeAnchor: true, RejectSelfSigned: true}
	return Options{
		ForbidExperimental:       true,
		ForbidDraftProfiles:      true,
		AllowedCredentialFormats: FormatSDJWTVC | FormatMsoMdoc,
		IssuerX5C:                all,
		StatusListTokenX5C:       all,

		RequirePAR:                        true,
		RequireDPoP:                       true,
		RequireAuthorizationResponseIss:   true,
		RequireScopeAuthorization:         true,
		RequireIssuerMetadataScopes:       true,
		RequireNonceEndpointForKeyBinding: true,
		RequestSignedIssuerMetadata:       true,
		SignedMetadataX5C:                 all,
		RequireClientAuthentication:       true,
		AttestationX5C:                    all,

		RequireSignedRequestByReference: true,
		RequireDirectPostJWT:            true,
		RequireDCAPIJWT:                 true,
		AllowedClientIDPrefixes:         ClientIDPrefixX509Hash,
		RequestObjectX5C:                all,
		ResponseEncryption: ResponseEncryptionRules{
			ECDHESOnly:             true,
			P256Only:               true,
			GCMOnly:                true,
			RequireVerifierGCMBoth: true,
		},
		AlwaysKeyBindingWhenConfirmed: true,
	}
}

// X5CRules are the certificate rules HAIP 1.0 states for every x5c-signed
// artifact it profiles.
type X5CRules struct {
	// Require makes the x5c JOSE header the only way to resolve the signing
	// key.
	Require bool
	// ExcludeAnchor refuses an x5c chain that includes the trust anchor
	// certificate.
	ExcludeAnchor bool
	// RejectSelfSigned refuses a self-signed signing certificate.
	RejectSelfSigned bool
}

// Union returns the rules that r or s turns on.
func (r X5CRules) Union(s X5CRules) X5CRules {
	return X5CRules{
		Require:          r.Require || s.Require,
		ExcludeAnchor:    r.ExcludeAnchor || s.ExcludeAnchor,
		RejectSelfSigned: r.RejectSelfSigned || s.RejectSelfSigned,
	}
}

// ResponseEncryptionRules restrict the JWE of an encrypted Authorization
// Response (OpenID4VP 1.0 §8.3). The zero value is OpenID4VP 1.0: ECDH-ES
// family key agreement on P-256, P-384 or P-521 with the alg the Verifier's
// JWK names (§8.3: "The alg parameter MUST be present in the JWKs"), and any
// content encryption the library supports.
type ResponseEncryptionRules struct {
	// ECDHESOnly accepts only the key agreement alg ECDH-ES.
	ECDHESOnly bool
	// P256Only accepts only Verifier keys on P-256.
	P256Only bool
	// GCMOnly accepts only the content encryption A128GCM and A256GCM.
	GCMOnly bool
	// RequireVerifierGCMBoth refuses Verifier metadata whose
	// encrypted_response_enc_values_supported does not list both A128GCM and
	// A256GCM.
	RequireVerifierGCMBoth bool
}

// CredentialFormats is a set of Credential Format Identifiers. The zero value
// is no restriction.
type CredentialFormats uint8

// Credential Format Identifiers of OpenID4VCI 1.0 Appendix A and OpenID4VP
// 1.0 Appendix B.
const (
	// FormatSDJWTVC is dc+sd-jwt (IETF SD-JWT VC).
	FormatSDJWTVC CredentialFormats = 1 << iota
	// FormatMsoMdoc is mso_mdoc (ISO mdoc).
	FormatMsoMdoc
	// FormatJWTVCJSON is jwt_vc_json (W3C VCDM secured with JOSE).
	FormatJWTVCJSON
	// FormatLDPVC is ldp_vc (W3C VCDM secured with Data Integrity).
	FormatLDPVC
	// FormatJWTVCJSONLD is jwt_vc_json-ld.
	FormatJWTVCJSONLD
)

var credentialFormatIdentifiers = map[string]CredentialFormats{
	"dc+sd-jwt":      FormatSDJWTVC,
	"mso_mdoc":       FormatMsoMdoc,
	"jwt_vc_json":    FormatJWTVCJSON,
	"ldp_vc":         FormatLDPVC,
	"jwt_vc_json-ld": FormatJWTVCJSONLD,
}

// Allows reports whether identifier is in s. An empty set allows every
// identifier; a non-empty one allows only its members, compared exactly.
func (s CredentialFormats) Allows(identifier string) bool {
	if s == 0 {
		return true
	}
	member, ok := credentialFormatIdentifiers[identifier]
	return ok && s&member != 0
}

// String lists the identifiers in s, or "any" for the empty set.
func (s CredentialFormats) String() string {
	return setString(uint16(s), credentialFormatNames)
}

var credentialFormatNames = []string{"dc+sd-jwt", "mso_mdoc", "jwt_vc_json", "ldp_vc", "jwt_vc_json-ld"}

// ClientIDPrefixes is a set of OpenID4VP 1.0 §5.9.3 Client Identifier
// Prefixes. The zero value is no restriction.
type ClientIDPrefixes uint16

// Client Identifier Prefixes of OpenID4VP 1.0 §5.9.3 and Appendix A.2.
const (
	// ClientIDPrefixPreRegistered is a Client Identifier without a prefix
	// (§5.9.2).
	ClientIDPrefixPreRegistered ClientIDPrefixes = 1 << iota
	ClientIDPrefixRedirectURI
	ClientIDPrefixOpenIDFederation
	ClientIDPrefixDecentralizedIdentifier
	ClientIDPrefixVerifierAttestation
	ClientIDPrefixX509SanDNS
	ClientIDPrefixX509Hash
	ClientIDPrefixOrigin
)

var clientIDPrefixNames = []string{
	"pre-registered", "redirect_uri", "openid_federation", "decentralized_identifier",
	"verifier_attestation", "x509_san_dns", "x509_hash", "origin",
}

// Allows reports whether the Client Identifier Prefix named prefix is in s,
// with "pre-registered" naming a Client Identifier without a prefix. An empty
// set allows every prefix.
func (s ClientIDPrefixes) Allows(prefix string) bool {
	if s == 0 {
		return true
	}
	for index, name := range clientIDPrefixNames {
		if name == prefix {
			return s&(1<<index) != 0
		}
	}
	return false
}

// String lists the prefixes in s, or "any" for the empty set.
func (s ClientIDPrefixes) String() string {
	return setString(uint16(s), clientIDPrefixNames)
}

func setString(bits uint16, names []string) string {
	if bits == 0 {
		return "any"
	}
	var members []string
	for index, name := range names {
		if bits&(1<<index) != 0 {
			members = append(members, name)
		}
	}
	return strings.Join(members, ",")
}
