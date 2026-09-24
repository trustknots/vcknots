// Package profile names the protocol policy the wallet enforces on
// OpenID4VCI 1.0 issuance and OpenID4VP 1.0 presentation.
//
// HAIP 1.0 is a set of constraints on top of those specifications, not a new
// wire protocol, so it is a policy value rather than a separate plugin. The
// draft protocol versions (OpenID4VCI Draft 13, OpenID4VP Draft 24) are
// outside any profile.
package profile

import (
	"fmt"

	"github.com/trustknots/vcknots/wallet/common"
)

// Profile is a protocol policy.
type Profile string

const (
	// Final is OpenID4VCI 1.0 / OpenID4VP 1.0 without additional constraints.
	Final Profile = "final"
	// HAIP is HAIP 1.0 constraints on top of Final.
	HAIP Profile = "haip"
)

// ErrUnknownProfile reports a Profile value other than "", Final and HAIP.
var ErrUnknownProfile = common.NewCodedError("unknown_profile", "unknown protocol profile")

// Normalize returns Final for the zero value and wraps ErrUnknownProfile for
// unknown values.
func (p Profile) Normalize() (Profile, error) {
	switch p {
	case "", Final:
		return Final, nil
	case HAIP:
		return HAIP, nil
	default:
		return "", fmt.Errorf("%w %q", ErrUnknownProfile, string(p))
	}
}

// IsHAIP reports whether this profile is HAIP. Unknown and zero values are not
// HAIP; callers must Normalize first when they need a validated value.
func (p Profile) IsHAIP() bool {
	return p == HAIP
}

// Carrier is implemented by protocol plugins that report the profile they
// enforce. The wallet refuses a plugin whose profile differs from its own,
// and under HAIP a plugin that is not a Carrier.
type Carrier interface {
	ProtocolProfile() Profile
}
