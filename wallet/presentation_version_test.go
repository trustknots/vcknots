package wallet

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	"github.com/trustknots/vcknots/wallet/profile"
)

// A Presentation Exchange request handed to the OpenID4VP 1.0 entry point is
// named a Draft 24 request, and the wallet admits it as one when Draft 24 is
// enabled; a wallet that runs 1.0 only refuses it.
func TestWallet_AdmitPresentationRequestUnderVersion(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	uri := draft24PresentationURI(fixture.baseURL, "direct_post", "")
	_, refused := fixture.wallet.ParsePresentationRequest(t.Context(), uri)
	require.ErrorIs(t, refused, oid4vp.ErrProtocolVersionMismatch)
	code, _ := ErrorCode(refused)
	require.Equal(t, "oid4vp_version_mismatch", code)

	handle, err := fixture.wallet.AdmitPresentationRequestUnderVersion(t.Context(), refused)
	require.NoError(t, err)
	require.True(t, handle.Draft24())

	finalOnly, err := NewWalletWithConfig(Config{Profiles: []profile.Profile{profile.Final()}})
	require.NoError(t, err)
	_, refused = finalOnly.ParsePresentationRequest(t.Context(), uri)
	require.ErrorIs(t, refused, oid4vp.ErrProtocolVersionMismatch)
	_, err = finalOnly.AdmitPresentationRequestUnderVersion(t.Context(), refused)
	require.ErrorIs(t, err, ErrProfileForbidsDraft)
}
