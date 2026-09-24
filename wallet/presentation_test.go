package wallet

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/presenter"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
)

const identityDCQLQuery = `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["given_name"]}]}]}`

// A handle answers only through the presenter that admitted it, so the trust
// policy that admitted a request is the one that answers it; nothing is sent
// for a handle another presenter admitted.
func TestWallet_SubmitPresentationRefusesAForeignHandle(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	holder := fixture.key.PublicKey()
	fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro"})

	otherPresenter, err := presenter.NewPresentationDispatcher(presenter.WithPlugin(presenter.Oid4vp, &oid4vp.Oid4vpPresenter{}))
	require.NoError(t, err)
	other, err := NewWalletWithConfig(Config{Presenter: otherPresenter, Storeless: true})
	require.NoError(t, err)
	foreign, err := other.ParsePresentationRequest(t.Context(), presentationURI(fixture.baseURL, identityDCQLQuery))
	require.NoError(t, err)

	selections, err := fixture.wallet.SelectCredentials(t.Context(), foreign)
	require.NoError(t, err)
	_, err = fixture.wallet.SubmitPresentation(t.Context(), foreign, Presentation{Key: fixture.key, Credentials: selections})
	require.ErrorIs(t, err, oid4vp.ErrRequestNotAdmittedHere)
	_, err = fixture.wallet.DeclinePresentation(t.Context(), foreign, "access_denied", "")
	require.ErrorIs(t, err, oid4vp.ErrRequestNotAdmittedHere)
	require.Len(t, fixture.posted, 0)
}

// DeclinePresentation answers at the endpoint the request was admitted with.
func TestWallet_DeclinePresentation(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	request := parsedPresentationRequest(t, fixture, presentationURI(fixture.baseURL, identityDCQLQuery))

	result, err := fixture.wallet.DeclinePresentation(t.Context(), request, "access_denied", "the holder declined")
	require.NoError(t, err)
	require.Equal(t, fixture.baseURL+"/done", result.RedirectURI)
	form := <-fixture.posted
	require.Equal(t, "access_denied", form.Get("error"))
	require.Equal(t, "the holder declined", form.Get("error_description"))
	require.Equal(t, "state-to-preserve", form.Get("state"))
	require.Empty(t, form.Get("vp_token"))
}

// The library's own choice names the claims a consent screen shows, and
// submitting it discloses exactly those.
func TestWallet_SelectCredentialsNamesTheDisclosedClaims(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	holder := fixture.key.PublicKey()
	fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro", "family_name": "Yamada"})
	fixture.receive("urn:test:address", &holder, nil, map[string]string{"street_address": "1 Example St"})
	query := `{"credentials":[` +
		`{"id":"given","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["given_name"]}]},` +
		`{"id":"family","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["family_name"]}]}]}`
	request := parsedPresentationRequest(t, fixture, presentationURI(fixture.baseURL, query))

	selections, err := fixture.wallet.SelectCredentials(t.Context(), request)
	require.NoError(t, err)
	require.Equal(t, []CredentialSelection{{
		CredentialID:    storedCredentialID(t, fixture.wallet, "urn:test:identity"),
		QueryIDs:        []string{"given", "family"},
		DisclosedClaims: []string{"given_name", "family_name"},
	}}, selections)

	_, err = presentSelections(t, fixture.wallet, request, fixture.key, selections)
	require.NoError(t, err)
	tokens := postedVPToken(t, fixture)
	require.Equal(t, []string{"given_name"}, disclosedNames(t, tokens["given"][0]))
	require.Equal(t, []string{"family_name"}, disclosedNames(t, tokens["family"][0]))
}

// Every error the presentation methods return carries a library code, and
// input the wallet refuses before any I/O is invalid_argument.
func TestWallet_PresentationErrorsAreCoded(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	request := parsedPresentationRequest(t, fixture, presentationURI(fixture.baseURL, identityDCQLQuery))

	_, err := fixture.wallet.SubmitPresentation(t.Context(), nil, Presentation{})
	require.ErrorIs(t, err, ErrInvalidArgument)
	_, err = fixture.wallet.SelectCredentials(t.Context(), nil)
	require.ErrorIs(t, err, ErrInvalidArgument)
	_, err = fixture.wallet.DeclinePresentation(t.Context(), nil, "access_denied", "")
	require.ErrorIs(t, err, ErrInvalidArgument)

	_, err = presentSelections(t, fixture.wallet, request, nil, []CredentialSelection{{CredentialID: "any", QueryIDs: []string{"pid"}}})
	require.ErrorIs(t, err, ErrInvalidArgument)

	for _, err := range []error{
		func() error {
			_, err := fixture.wallet.ParsePresentationRequest(t.Context(), "not a request")
			return err
		}(),
		func() error { _, err := fixture.wallet.SelectCredentials(t.Context(), request); return err }(),
		func() error {
			_, err := presentSelections(t, fixture.wallet, request, fixture.key, []CredentialSelection{{CredentialID: "missing", QueryIDs: []string{"pid"}}})
			return err
		}(),
	} {
		require.Error(t, err)
		code, ok := ErrorCode(err)
		require.True(t, ok, "uncoded error: %v", err)
		require.NotEqual(t, "unclassified", code, err.Error())
	}
	require.Len(t, fixture.posted, 0)
}
