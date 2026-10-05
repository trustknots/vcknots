package oid4vp

import (
	"context"
	"net/url"

	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp/federation"
)

// trustedAuthorityOpenIDFederation is the openid_federation Trusted
// Authorities Query type (OID4VP 1.0 Section 6.1.1.3).
const trustedAuthorityOpenIDFederation = "openid_federation"

// ResolveFederationTrustedAuthorities prepares candidates for the
// openid_federation trusted_authorities of r's DCQL query (OID4VP 1.0 Section
// 6.1.1.3). For every candidate whose format such a query names, it resolves
// the Trust Chains from the candidate's Issuer to the Trust Anchors of the
// admitting presenter's RequestObjectValidation.Federation, under that
// configuration's client and bounds, and sets FederationEntityIDs to the
// Entity Identifiers of the valid chains. An issuer without a valid chain, or
// a presenter without Trust Anchors, leaves the field empty, so the query
// matches nothing. Only a context that ends is an error.
func (r *AdmittedRequest) ResolveFederationTrustedAuthorities(ctx context.Context, candidates []DCQLCredentialCandidate) error {
	if r == nil || r.req == nil || r.req.DcqlQuery == nil || r.admittedBy == nil {
		return nil
	}
	formats := map[string]bool{}
	for _, query := range r.req.DcqlQuery.Credentials {
		for _, authority := range query.TrustedAuthorities {
			if authority.Type == trustedAuthorityOpenIDFederation {
				formats[query.Format] = true
			}
		}
	}
	options := r.admittedBy.RequestObjectValidation
	if len(formats) == 0 || options == nil || options.Federation == nil || len(options.Federation.TrustAnchors) == 0 {
		return nil
	}
	resolver := newFederationResolver(*options, r.admittedBy.httpClient())
	resolved := map[string][]string{}
	for i := range candidates {
		candidate := &candidates[i]
		if !formats[candidate.Format] || !isEntityIdentifier(candidate.Issuer) {
			continue
		}
		entityIDs, done := resolved[candidate.Issuer]
		if !done {
			chains, err := resolver.ResolveTrustChains(ctx, candidate.Issuer)
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			if err == nil {
				for _, chain := range chains {
					for _, id := range federation.TrustPathEntityIDs(chain) {
						if !containsString(entityIDs, id) {
							entityIDs = append(entityIDs, id)
						}
					}
				}
			}
			resolved[candidate.Issuer] = entityIDs
		}
		candidate.FederationEntityIDs = append([]string(nil), entityIDs...)
	}
	return nil
}

// isEntityIdentifier reports whether id can be an OpenID Federation Entity
// Identifier: an https URL with a host and no query or fragment (OpenID
// Federation 1.0 Section 1.2).
func isEntityIdentifier(id string) bool {
	parsed, err := url.Parse(id)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.RawQuery == "" && parsed.Fragment == ""
}
