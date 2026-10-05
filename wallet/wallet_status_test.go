package wallet

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustknots/vcknots/wallet/credential/statuslist"
	"github.com/trustknots/vcknots/wallet/experimental"
	"github.com/trustknots/vcknots/wallet/profile"
)

// HAIP 1.0 §6.1: a Status List checker built for a HAIP wallet must not run
// under Final because the caller did not repeat the profile, or its token
// x5c rules would not apply. The zero Profile is Final everywhere, including
// here, so a checker that does not name
// the wallet's profile is refused rather than run under weaker rules.
func TestStatusListCheckerRequiresTheWalletProfile(t *testing.T) {
	strict, err := profile.Final().With(profile.HAIPOptions())
	require.NoError(t, err)
	for _, p := range []profile.Profile{profile.Final(), profile.HAIP(), strict} {
		t.Run(p.String(), func(t *testing.T) {
			w, err := NewWalletWithConfig(Config{Profiles: []profile.Profile{p}, Storeless: true})
			require.NoError(t, err)
			checker, err := w.StatusListChecker(statuslist.Checker{Profile: p})
			require.NoError(t, err)
			require.Equal(t, p, checker.Profile)
		})
	}

	haip, err := NewWalletWithConfig(Config{Profiles: []profile.Profile{profile.HAIP()}, Storeless: true})
	require.NoError(t, err)
	// Final().With(HAIPOptions()) is HAIP(), whichever way it was built.
	_, err = haip.StatusListChecker(statuslist.Checker{Profile: strict})
	require.NoError(t, err)
	_, err = haip.StatusListChecker(statuslist.Checker{})
	requireCoded(t, err, ErrProfileMismatch)
	partial, err := profile.Final().With(profile.Options{RequireDPoP: true})
	require.NoError(t, err)
	_, err = haip.StatusListChecker(statuslist.Checker{Profile: partial})
	requireCoded(t, err, ErrProfileMismatch)
	_, err = haip.StatusListChecker(statuslist.Checker{Profile: profile.HAIP(), Experimental: experimental.Transport{AllowHTTP: true}})
	require.ErrorIs(t, err, statuslist.ErrStatusListInsecureTransportForbidden)

	final, err := NewWalletWithConfig(Config{Profiles: []profile.Profile{profile.Final()}, Storeless: true})
	require.NoError(t, err)
	checker, err := final.StatusListChecker(statuslist.Checker{Experimental: experimental.Transport{AllowHTTP: true}})
	require.NoError(t, err)
	require.True(t, checker.Experimental.AllowHTTP)
}
