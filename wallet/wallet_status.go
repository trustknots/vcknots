package wallet

import (
	"fmt"

	"github.com/trustknots/vcknots/wallet/credential/statuslist"
	"github.com/trustknots/vcknots/wallet/experimental"
	"github.com/trustknots/vcknots/wallet/profile"
)

// StatusListChecker returns a copy of base that checks Token Status Lists
// under the wallet's 1.0 profile, after checking that base names it: a
// Checker applies the Options of its own Profile (for HAIP 1.0 Section 6.1,
// the Status List Token's key in its x5c header, no trust anchor in it, no
// self-signed leaf), so a Checker whose Profile differs from the wallet's is
// refused with ErrProfileMismatch. As everywhere, the zero Profile is
// profile.Final, so a Checker for a wallet with options sets Profile. Under
// Options.ForbidExperimental, a Checker that sets Experimental is refused
// before anything is fetched.
func (w *Wallet) StatusListChecker(base statuslist.Checker) (*statuslist.Checker, error) {
	checker := base
	if checker.Profile != w.profile {
		return nil, fmt.Errorf("%w: the Status List checker names %s, the wallet runs %s", ErrProfileMismatch, checker.Profile, w.profile)
	}
	if checker.Profile.Options().ForbidExperimental && checker.Experimental != (experimental.Transport{}) {
		return nil, fmt.Errorf("%w: %w does not permit Checker.Experimental: %w", ErrInvalidArgument, profile.Refused("ForbidExperimental"), statuslist.ErrStatusListInsecureTransportForbidden)
	}
	return &checker, nil
}
