package oid4vp

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/internal/testutil"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp/federation"
)

// federationDCQLRequest admits a DCQL query whose one credential query lists
// the openid_federation values, on a presenter trusting anchors.
func federationDCQLRequest(f *federationRequestFixture, anchors []federation.TrustAnchor, values ...string) *AdmittedRequest {
	presenter := &Oid4vpPresenter{
		HTTPClient: f.server.Client(),
		RequestObjectValidation: &RequestObjectValidationOptions{
			Federation: &FederationTrustOptions{TrustAnchors: anchors},
		},
	}
	query := &DcqlQuery{Credentials: []CredentialQuery{{
		ID: "pid", Format: "dc+sd-jwt", Meta: map[string]any{},
		TrustedAuthorities: []TrustedAuthority{{Type: "openid_federation", Values: values}},
	}}}
	return &AdmittedRequest{req: &CredentialPresentationRequest{DcqlQuery: query}, admittedBy: presenter}
}

func (f *federationRequestFixture) trustAnchor() federation.TrustAnchor {
	return federation.TrustAnchor{EntityID: f.anchorID, JWKS: publicJWKS(f.anchorKey, federationAnchorKid)}
}

func federationCandidates(issuers ...string) []DCQLCredentialCandidate {
	bound := true
	candidates := make([]DCQLCredentialCandidate, 0, len(issuers))
	for _, issuer := range issuers {
		candidates = append(candidates, DCQLCredentialCandidate{ID: issuer, Format: "dc+sd-jwt", Issuer: issuer, HolderBound: &bound})
	}
	return candidates
}

// OID4VP 1.0 Section 6.1.1.3: a credential matches an openid_federation value
// when a valid trust path from its issuer includes that Entity Identifier. The
// path must end at a Trust Anchor the wallet configured.
func TestDCQLOpenIDFederationTrustedAuthorities(t *testing.T) {
	f := newFederationRequestFixture(t)
	outsider := f.server.URL + "/outsider"

	t.Run("an issuer below the listed anchor matches", func(t *testing.T) {
		request := federationDCQLRequest(f, []federation.TrustAnchor{f.trustAnchor()}, f.anchorID)
		candidates := federationCandidates(outsider, f.verifierID)
		require.NoError(t, request.ResolveFederationTrustedAuthorities(t.Context(), candidates))
		require.Empty(t, candidates[0].FederationEntityIDs)
		require.Equal(t, []string{f.verifierID, f.anchorID}, candidates[1].FederationEntityIDs)

		query := request.Request().DcqlQuery
		selected, err := ResolveSatisfiableDCQLCredentials(query, candidates)
		require.NoError(t, err)
		require.Len(t, selected, 1)
		require.Equal(t, f.verifierID, selected[0].CandidateID)
		require.NoError(t, ValidateDCQLMatches(query, candidates, selected))
	})

	t.Run("an anchor the wallet does not configure matches nothing", func(t *testing.T) {
		request := federationDCQLRequest(f, []federation.TrustAnchor{f.trustAnchor()}, "https://other-anchor.example")
		candidates := federationCandidates(f.verifierID)
		require.NoError(t, request.ResolveFederationTrustedAuthorities(t.Context(), candidates))
		_, err := ResolveSatisfiableDCQLCredentials(request.Request().DcqlQuery, candidates)
		require.ErrorIs(t, err, ErrDCQLSelectionUnsatisfied)
	})

	t.Run("an anchor configured with other keys matches nothing", func(t *testing.T) {
		wrong := federation.TrustAnchor{EntityID: f.anchorID, JWKS: publicJWKS(testutil.NewP256Key(t), federationAnchorKid)}
		request := federationDCQLRequest(f, []federation.TrustAnchor{wrong}, f.anchorID)
		candidates := federationCandidates(f.verifierID)
		require.NoError(t, request.ResolveFederationTrustedAuthorities(t.Context(), candidates))
		require.Empty(t, candidates[0].FederationEntityIDs)
		_, err := ResolveSatisfiableDCQLCredentials(request.Request().DcqlQuery, candidates)
		require.ErrorIs(t, err, ErrDCQLSelectionUnsatisfied)
	})

	t.Run("without configured anchors nothing is fetched and nothing matches", func(t *testing.T) {
		var fetched atomic.Int32
		request := federationDCQLRequest(f, nil, f.anchorID)
		request.admittedBy.HTTPClient = countingClient(f.server.Client(), &fetched)
		candidates := federationCandidates(f.verifierID)
		require.NoError(t, request.ResolveFederationTrustedAuthorities(t.Context(), candidates))
		require.Zero(t, fetched.Load())
		_, err := ResolveSatisfiableDCQLCredentials(request.Request().DcqlQuery, candidates)
		require.ErrorIs(t, err, ErrDCQLSelectionUnsatisfied)
	})

	t.Run("an ended context is an error", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		request := federationDCQLRequest(f, []federation.TrustAnchor{f.trustAnchor()}, f.anchorID)
		require.ErrorIs(t, request.ResolveFederationTrustedAuthorities(ctx, federationCandidates(f.verifierID)), context.Canceled)
	})
}

// countingClient is client with every request counted in fetched.
func countingClient(client *http.Client, fetched *atomic.Int32) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		fetched.Add(1)
		return client.Transport.RoundTrip(r)
	})}
}
