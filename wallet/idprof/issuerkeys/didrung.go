package issuerkeys

import (
	"context"
	"net/url"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4"

	"github.com/trustknots/vcknots/wallet/idprof/plugins/did"
)

// didRung is rung 3: a key from a DID document.
//
// The DID is the credential's `iss`; a `kid` that names a verification method
// of another DID gives the rung nothing. A DID document proves only that
// whoever controls the DID published these keys, not that the controller is the
// Credential Issuer, so a resolved key becomes a candidate only once something
// binds the DID to that issuer:
//
//  1. the Credential Issuer Metadata `jwks` names the same key (non-normative,
//     see Mechanisms.IssuerMetadataJWKS);
//  2. the credential's own `vc.issuer` object names both the DID and the
//     Credential Issuer (self-asserted, see Mechanisms.CredentialIssuerBinding);
//  3. a DIF Well Known DID Configuration served by the Credential Issuer's
//     origin links that origin to the DID.
//
// A key with none of them is refused outright, with ErrDIDOnlyTrustUnsupported,
// rather than being dropped so the ladder can fall through to a weaker rung:
// "signed by a DID that claims to be this issuer" is a situation a caller must
// see, not one to resolve by trying something else.
func (r *Resolver) didRung(
	ctx context.Context,
	request Request,
	metadataKeys []jose.JSONWebKey,
) ([]Candidate, MechanismDiagnostic, error) {
	diagnostic := MechanismDiagnostic{Mechanism: RungDID}

	didValue := didReference(request.Issuer)
	if didValue != request.Issuer {
		// A DID URL is not an issuer identifier.
		didValue = ""
	}
	kidDID := didReference(request.KeyID)
	switch {
	case didValue == "" && kidDID != "":
		diagnostic.Failure = "kid names a DID but the issuer is not that DID"
		return nil, diagnostic, nil
	case didValue == "":
		diagnostic.Failure = "issuer is not a DID"
		return nil, diagnostic, nil
	case kidDID != "" && kidDID != didValue:
		diagnostic.Failure = "kid names a DID other than the issuer"
		return nil, diagnostic, nil
	}
	switchName, supported := didMethodSwitch(didValue)
	if !supported {
		diagnostic.Failure = "DID method is not supported"
		return nil, diagnostic, nil
	}
	if !r.didMethodAllowed(didValue) {
		diagnostic.Failure = failureDisabled
		diagnostic.DisabledBy = []string{switchName}
		return nil, diagnostic, nil
	}
	diagnostic.Attempted = true

	keys, err := r.resolveDIDKeys(ctx, didValue, request.KeyID, request.CredentialIssuer)
	if err != nil {
		diagnostic.Failure = failureReason(err)
		return nil, diagnostic, nil
	}

	// The `vc.issuer` binding is a read of the credential this call already
	// holds; the DID Configuration binding is an outbound request, so it is
	// made only if the cheaper bindings have not already answered for a key.
	credentialIssuerBound := r.credentialIssuerBinds(request)
	didConfigurationBound := r.lazyDIDConfigurationBinding(ctx, didValue, request)

	var candidates []Candidate
	for _, key := range keys {
		mechanism, bound := r.didBinding(key, metadataKeys, credentialIssuerBound, didConfigurationBound)
		if !bound {
			continue
		}
		candidates = append(candidates, Candidate{
			Key:       key,
			Issuer:    didValue,
			Mechanism: mechanism,
			DID:       didValue,
		})
	}
	if len(candidates) == 0 {
		diagnostic.Failure = "DID-only trust not accepted without metadata/config binding"
		diagnostic.DisabledBy = r.switchedOffBindings(request)
		return nil, diagnostic, newMechanismError(ErrDIDOnlyTrustUnsupported, diagnostic.Failure)
	}
	diagnostic.CandidateCount = len(candidates)
	return candidates, diagnostic, nil
}

// switchedOffBindings names the binding switches that are off and would have
// applied to request's format. They are what a holder can turn on to let a DID
// the ladder refused as unbound become bound.
func (r *Resolver) switchedOffBindings(request Request) []string {
	var off []string
	if !r.Mechanisms.IssuerMetadataJWKS {
		off = append(off, SwitchIssuerMetadataJWKS)
	}
	if request.CredentialFormat == FormatJWTVCJSON {
		if !r.Mechanisms.CredentialIssuerBinding {
			off = append(off, SwitchCredentialIssuerBinding)
		}
		if !r.Mechanisms.DIDConfiguration {
			off = append(off, SwitchDIDConfiguration)
		}
	}
	return off
}

// didBinding reports which binding makes key usable for this issuer.
func (r *Resolver) didBinding(
	key jose.JSONWebKey,
	metadataKeys []jose.JSONWebKey,
	credentialIssuerBound bool,
	didConfigurationBound func() bool,
) (Mechanism, bool) {
	if anyPublicKeyMatches(metadataKeys, key) {
		return MechanismDIDMetadataBinding, true
	}
	if credentialIssuerBound {
		return MechanismDIDCredentialIssuerBinding, true
	}
	if didConfigurationBound() {
		return MechanismDIDConfigurationBinding, true
	}
	return "", false
}

// didMethodSwitch reports the Mechanisms switch that governs the DID's method,
// and false for a method this package does not resolve.
func didMethodSwitch(didValue string) (string, bool) {
	switch {
	case strings.HasPrefix(didValue, "did:jwk:"):
		return SwitchDIDJWK, true
	case strings.HasPrefix(didValue, "did:key:"):
		return SwitchDIDKey, true
	case strings.HasPrefix(didValue, "did:web:"):
		return SwitchDIDWeb, true
	default:
		return "", false
	}
}

// didMethodAllowed reports whether the configuration admits the DID's method.
func (r *Resolver) didMethodAllowed(didValue string) bool {
	switch switchName, _ := didMethodSwitch(didValue); switchName {
	case SwitchDIDJWK:
		return r.Mechanisms.DIDJWK
	case SwitchDIDKey:
		return r.Mechanisms.DIDKey
	case SwitchDIDWeb:
		return r.Mechanisms.DIDWeb
	default:
		return false
	}
}

// resolveDIDKeys resolves didValue to its verification keys.
//
// For did:web the document's host is checked against the Credential Issuer's
// before anything is requested. The check is worth making early twice over: a
// DID document served by an unrelated host could never bind to this issuance
// anyway, and requesting it would tell that host a credential is being
// verified. The comparison includes the port, because a different port is a
// different origin; a port that is the scheme's default is the same origin as
// no port at all.
//
// A did:web document may declare many assertion keys, and a `kid` that names
// one of them - as a full DID URL, as a relative "#fragment", or as a bare
// fragment - narrows the result to that key. A `kid` of another shape narrows
// nothing. did:key and did:jwk carry a single key in the identifier, so there
// is nothing to narrow.
func (r *Resolver) resolveDIDKeys(ctx context.Context, didValue, keyID, credentialIssuer string) ([]jose.JSONWebKey, error) {
	web := strings.HasPrefix(didValue, "did:web:")
	if web {
		documentURL, err := did.WebDocumentURL(didValue)
		if err != nil {
			return nil, newMechanismError(ErrDIDResolutionFailed, "did:web identifier does not name a document URL")
		}
		issuerURL, err := url.Parse(credentialIssuer)
		if err != nil || issuerURL.Host == "" {
			return nil, newMechanismError(ErrDIDHostNotBound, "credential issuer is not a URL with a host")
		}
		if originAuthority(documentURL) != originAuthority(issuerURL) {
			return nil, newMechanismError(ErrDIDHostNotBound, "did:web host is not the credential issuer host")
		}
	}

	set, err := r.didResolver().Resolve(ctx, didValue)
	if err != nil || set == nil {
		return nil, newMechanismError(ErrDIDResolutionFailed, "DID resolved to no verification key")
	}
	var keys []jose.JSONWebKey
	for _, key := range set.Keys {
		if isSignatureKey(key) {
			keys = append(keys, key)
		}
	}
	if web {
		if wanted := verificationMethodID(didValue, keyID); wanted != "" {
			keys = slices.DeleteFunc(keys, func(key jose.JSONWebKey) bool { return key.KeyID != wanted })
		}
	}
	if len(keys) == 0 {
		return nil, newMechanismError(ErrDIDResolutionFailed, "DID resolved to no verification key")
	}
	return keys, nil
}

// verificationMethodID returns the verification method identifier a `kid`
// names within didValue's document, or the empty string when the `kid` does
// not name one in a form this package recognises.
func verificationMethodID(didValue, keyID string) string {
	switch {
	case keyID == "":
		return ""
	case strings.HasPrefix(keyID, didValue+"#"):
		return keyID
	case strings.HasPrefix(keyID, "#"):
		return didValue + keyID
	case !strings.ContainsAny(keyID, `:#/\`):
		return didValue + "#" + keyID
	default:
		return ""
	}
}

// originAuthority returns the lowercased host of u with its port, the port
// dropped when it is the default for u's scheme, which is the host part of the
// origin RFC 6454 compares.
func originAuthority(u *url.URL) string {
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	if port == "" {
		return host
	}
	return host + ":" + port
}

// credentialIssuerBinds reports whether the credential's own signed claims link
// its DID issuer to this Credential Issuer.
//
// The evidence is inside the signature being verified, so it is only worth
// anything for a format that carries such a claim: the W3C JWT VC `vc.issuer`
// object. Both members must agree - the object's `id` with the credential's
// `iss`, its `credential_issuer` with the issuance's Credential Issuer - or the
// signer has not stated the link this rung needs.
func (r *Resolver) credentialIssuerBinds(request Request) bool {
	if request.CredentialFormat != FormatJWTVCJSON || !r.Mechanisms.CredentialIssuerBinding {
		return false
	}
	if !strings.HasPrefix(request.Issuer, "did:") {
		return false
	}
	credential, ok := request.Payload["vc"].(map[string]any)
	if !ok {
		return false
	}
	issuer, ok := credential["issuer"].(map[string]any)
	if !ok {
		return false
	}
	id, _ := issuer["id"].(string)
	credentialIssuer, _ := issuer["credential_issuer"].(string)
	return id == request.Issuer && credentialIssuer == request.CredentialIssuer
}

// lazyDIDConfigurationBinding returns a predicate that retrieves the Credential
// Issuer's DID Configuration the first time it is asked, and remembers the
// answer.
//
// It is lazy because the retrieval is an outbound request whose answer is only
// needed for a key the cheaper bindings did not already cover, and memoised
// because the answer is the same for every key of one DID.
func (r *Resolver) lazyDIDConfigurationBinding(ctx context.Context, didValue string, request Request) func() bool {
	var asked, bound bool
	return func() bool {
		if asked {
			return bound
		}
		asked = true
		if request.CredentialFormat != FormatJWTVCJSON || !r.Mechanisms.DIDConfiguration {
			return false
		}
		// A DID Configuration that cannot be retrieved or does not verify
		// simply does not bind. It is not the rung's failure: another binding
		// may still cover the key, and if none does the caller is told the DID
		// was unbound, which is the accurate statement either way.
		bound, _ = r.didConfigurationBinds(ctx, didValue, request)
		return bound
	}
}

// didResolver returns the DID resolver to use.
func (r *Resolver) didResolver() DIDResolver {
	if r.DID != nil {
		return r.DID
	}
	// did:web retrieval uses this resolver's HTTP client and document cap.
	return pluginDIDResolver{plugin: did.NewDIDPluginWithWeb(&did.DIDWebPlugin{
		HTTPClient:       r.HTTPClient,
		MaxDocumentBytes: r.maxDocumentBytes(),
	})}
}

// pluginDIDResolver adapts the library's DID profile plugins to DIDResolver.
type pluginDIDResolver struct {
	plugin *did.DIDPlugin
}

// Resolve returns the verification keys of the DID's identity profile within
// ctx.
func (p pluginDIDResolver) Resolve(ctx context.Context, didValue string) (*jose.JSONWebKeySet, error) {
	profile, err := p.plugin.ResolveContext(ctx, didValue)
	if err != nil {
		return nil, err
	}
	return profile.Keys, nil
}
