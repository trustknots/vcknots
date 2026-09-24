package federation

import (
	"context"
	"encoding/json"
	"net/url"
	"slices"
	"sort"
	"strings"

	"github.com/go-jose/go-jose/v4"
)

// VerifierEntityType is the Entity Type of an OpenID4VP Verifier (OpenID4VP
// 1.0 Section 11.2 registers openid_credential_verifier for OpenID
// Federation).
const VerifierEntityType = "openid_credential_verifier"

// VerifierTrust is what a validated Trust Chain establishes about a Verifier
// using the openid_federation Client Identifier Prefix.
type VerifierTrust struct {
	// TrustChain is the chain that authenticated the Verifier.
	TrustChain *TrustChain
	// Metadata is the final openid_credential_verifier metadata after the
	// chain's policies were applied. When it carries vp_formats_supported but
	// no vp_formats, vp_formats is set to the same value so a consumer of
	// either name reads the formats.
	Metadata map[string]any
	// RequestObjectJWKS are the keys the Verifier signs Request Objects
	// with: the Federation Entity Keys of its Entity Configuration.
	RequestObjectJWKS jose.JSONWebKeySet
	// OrganizationName, LogoURI, PolicyURI and HomepageURI are the
	// federation_entity display metadata (OpenID Federation 1.0 Section
	// 5.2.2) selected for the preferred locales, each empty when absent.
	// HomepageURI is organization_uri, falling back to homepage_uri.
	OrganizationName, LogoURI, PolicyURI, HomepageURI string
}

// ResolveVerifierTrust authenticates the Verifier entityID. When
// carriedTrustChain is non-nil, that chain is validated as supplied and must
// end at a configured Trust Anchor; otherwise the chain is discovered, and the
// shortest valid chain whose Verifier metadata can be derived is used.
// preferredLocales orders the language-tagged display metadata; empty means
// English.
func (r *Resolver) ResolveVerifierTrust(ctx context.Context, entityID string, carriedTrustChain []string, preferredLocales []string) (*VerifierTrust, error) {
	if len(r.TrustAnchors) == 0 {
		return nil, failure(ErrTrustAnchorNotConfigured, "trust anchors must be configured")
	}
	chain, metadata, err := r.verifierChainAndMetadata(ctx, entityID, carriedTrustChain)
	if err != nil {
		return nil, err
	}
	trust := &VerifierTrust{
		TrustChain:        chain,
		Metadata:          normalizeVerifierMetadata(metadata),
		RequestObjectJWKS: chain.Statements[0].JWKS,
	}
	if err := trust.setDisplayMetadata(preferredLocales); err != nil {
		return nil, err
	}
	return trust, nil
}

// verifierChainAndMetadata returns the Trust Chain that authenticates the
// Verifier and its derived openid_credential_verifier metadata.
func (r *Resolver) verifierChainAndMetadata(ctx context.Context, entityID string, carried []string) (*TrustChain, map[string]any, error) {
	if carried != nil {
		chain, err := ValidateTrustChain(carried, entityID, r.TrustAnchors, r.now())
		if err != nil {
			return nil, nil, err
		}
		metadata, err := DeriveEntityMetadata(chain, VerifierEntityType)
		if err != nil {
			return nil, nil, err
		}
		return chain, metadata, nil
	}
	chains, err := r.ResolveTrustChains(ctx, entityID)
	if err != nil {
		return nil, nil, err
	}
	var firstErr error
	for _, chain := range chains {
		metadata, err := DeriveEntityMetadata(chain, VerifierEntityType)
		if err == nil {
			return chain, metadata, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return nil, nil, firstErr
}

// normalizeVerifierMetadata mirrors vp_formats_supported into vp_formats when
// only the former is present, keeping both.
func normalizeVerifierMetadata(metadata map[string]any) map[string]any {
	if _, present := metadata["vp_formats"]; !present {
		if formats, present := metadata["vp_formats_supported"]; present {
			metadata["vp_formats"] = formats
		}
	}
	return metadata
}

// setDisplayMetadata derives the federation_entity metadata of the chain's
// subject, when its Entity Configuration has any, and selects the display
// values for the preferred locales.
func (t *VerifierTrust) setDisplayMetadata(preferredLocales []string) error {
	if _, present := t.TrustChain.Statements[0].Metadata[federationEntityType]; !present {
		return nil
	}
	metadata, err := DeriveEntityMetadata(t.TrustChain, federationEntityType)
	if err != nil {
		return err
	}
	if len(preferredLocales) == 0 {
		preferredLocales = []string{"en"}
	}
	t.OrganizationName = localizedMetadataString(metadata, "organization_name", preferredLocales)
	if t.LogoURI, err = localizedMetadataURI(metadata, "logo_uri", preferredLocales); err != nil {
		return err
	}
	if t.PolicyURI, err = localizedMetadataURI(metadata, "policy_uri", preferredLocales); err != nil {
		return err
	}
	// OpenID Federation 1.0 names the organization's web page
	// organization_uri; homepage_uri is the earlier spelling.
	if t.HomepageURI, err = localizedMetadataURI(metadata, "organization_uri", preferredLocales); err != nil {
		return err
	}
	if t.HomepageURI == "" {
		t.HomepageURI, err = localizedMetadataURI(metadata, "homepage_uri", preferredLocales)
	}
	return err
}

// localizedMetadataString selects the value of name for the preferred locales
// among its language-tagged members "name#<tag>" (OpenID Federation 1.0
// Section 5.2.2 uses the language tags of OpenID Connect Core Section 5.2),
// falling back to the untagged member.
func localizedMetadataString(metadata map[string]any, name string, preferredLocales []string) string {
	prefix := name + "#"
	var locales []string
	for key := range metadata {
		if strings.HasPrefix(key, prefix) && len(key) > len(prefix) {
			locales = append(locales, key[len(prefix):])
		}
	}
	// JSON object members have no order once decoded, so the last-resort
	// "first available" locale is the lexicographically first one.
	sort.Strings(locales)
	if locale, ok := selectLocale(locales, preferredLocales); ok {
		if localized, _ := metadata[prefix+locale].(string); localized != "" {
			return localized
		}
	}
	fallback, _ := metadata[name].(string)
	return fallback
}

// localizedMetadataURI is localizedMetadataString for a URI member, which must
// be an absolute URI.
func localizedMetadataURI(metadata map[string]any, name string, preferredLocales []string) (string, error) {
	value := localizedMetadataString(metadata, name, preferredLocales)
	if value == "" {
		return "", nil
	}
	parsed, err := url.Parse(value)
	if err != nil || !parsed.IsAbs() || ((parsed.Scheme == "https" || parsed.Scheme == "http") && parsed.Host == "") {
		return "", failure(ErrMetadataDerivationFailed, "%s metadata must be an absolute URI", name)
	}
	return value, nil
}

// selectLocale picks a locale from available by case-insensitive exact tag,
// then by primary language, then the first available one.
func selectLocale(available, preferred []string) (string, bool) {
	if len(available) == 0 {
		return "", false
	}
	for _, preference := range preferred {
		for _, locale := range available {
			if strings.EqualFold(locale, preference) {
				return locale, true
			}
		}
	}
	for _, preference := range preferred {
		language := primaryLanguage(preference)
		for _, locale := range available {
			if primaryLanguage(locale) == language {
				return locale, true
			}
		}
	}
	return available[0], true
}

func primaryLanguage(locale string) string {
	language, _, _ := strings.Cut(strings.ToLower(locale), "-")
	return language
}

// TrustPathEntityIDs returns the Entity Identifiers of a Trust Chain, each
// once: the subject first, then the subject and issuer of every statement in
// chain order, and the Trust Anchor last.
func TrustPathEntityIDs(chain *TrustChain) []string {
	if chain == nil {
		return nil
	}
	ids := []string{chain.SubjectEntityID}
	add := func(id string) {
		if !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	for _, statement := range chain.Statements {
		add(statement.Subject)
		add(statement.Issuer)
	}
	add(chain.TrustAnchorEntityID)
	return ids
}

// ParseTrustChainParameter reads a `trust_chain` value a Verifier supplied
// (OpenID Federation 1.0 Section 4.3; OpenID4VP 1.0 Section 5.9.3): a
// non-empty array of non-empty compact Entity Statements, given as a JSON
// array or as a string holding one.
func ParseTrustChainParameter(raw any) ([]string, error) {
	if text, ok := raw.(string); ok {
		var decoded any
		if err := json.Unmarshal([]byte(text), &decoded); err != nil {
			return nil, failure(ErrTrustChainInvalid, "trust_chain must be valid JSON")
		}
		raw = decoded
	}
	chain, ok := asNonEmptyStringArray(raw)
	if !ok || len(chain) == 0 {
		return nil, failure(ErrTrustChainInvalid, "trust_chain must be a non-empty string array")
	}
	return chain, nil
}

// AssertResponseURIAllowed requires endpoint, the endpoint the Authorization
// Response will reach, to be one of the redirect_uris of the Verifier metadata
// the Trust Chain produced, compared as exact strings. The Trust Chain is the
// only authenticated statement of the Verifier's endpoints.
func AssertResponseURIAllowed(metadata map[string]any, endpoint string) error {
	redirectURIs, _ := asStringArray(metadata["redirect_uris"])
	if endpoint == "" || !slices.Contains(redirectURIs, endpoint) {
		return failure(ErrResponseURINotRegistered, "the response endpoint must be one of the federation verifier metadata redirect_uris")
	}
	return nil
}
