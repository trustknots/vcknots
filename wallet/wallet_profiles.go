package wallet

import (
	"fmt"

	"github.com/trustknots/vcknots/wallet/profile"
)

// DefaultProfiles returns the profiles of a wallet whose Config.Profiles is
// empty: profile.Final with profile.Draft13 and profile.Draft24. The result
// is a fresh slice.
func DefaultProfiles() []profile.Profile {
	return []profile.Profile{profile.Final(), profile.Draft13(), profile.Draft24()}
}

// walletProfiles is a validated Config.Profiles.
type walletProfiles struct {
	// final is the OpenID4VCI 1.0 / OpenID4VP 1.0 profile.
	final   profile.Profile
	draft13 bool
	draft24 bool
}

// resolveProfiles validates Config.Profiles: exactly one 1.0 profile, each
// draft profile at most once, and no draft profile beside a 1.0 profile with
// Options.ForbidDraftProfiles.
func resolveProfiles(profiles []profile.Profile) (walletProfiles, error) {
	if len(profiles) == 0 {
		profiles = DefaultProfiles()
	}
	var resolved walletProfiles
	finals := 0
	for _, p := range profiles {
		switch p.Version() {
		case profile.VersionDraft13:
			if resolved.draft13 {
				return walletProfiles{}, fmt.Errorf("%w: Config.Profiles names profile.Draft13 twice", ErrInvalidArgument)
			}
			resolved.draft13 = true
		case profile.VersionDraft24:
			if resolved.draft24 {
				return walletProfiles{}, fmt.Errorf("%w: Config.Profiles names profile.Draft24 twice", ErrInvalidArgument)
			}
			resolved.draft24 = true
		default:
			finals++
			resolved.final = p
		}
	}
	if finals != 1 {
		return walletProfiles{}, fmt.Errorf("%w: Config.Profiles must name exactly one OpenID4VCI 1.0 / OpenID4VP 1.0 profile, got %d", ErrInvalidArgument, finals)
	}
	if resolved.final.Options().ForbidDraftProfiles && (resolved.draft13 || resolved.draft24) {
		return walletProfiles{}, fmt.Errorf("%w: %w forbids a draft profile in Config.Profiles beside %s", ErrProfileForbidsDraft, profile.Refused("ForbidDraftProfiles"), resolved.final)
	}
	return resolved, nil
}

// options returns the Options of the wallet's 1.0 profile.
func (w *Wallet) options() profile.Options {
	return w.profile.Options()
}

// requireDraft13 refuses an OpenID4VCI Draft 13 entry point unless
// Config.Profiles enables profile.Draft13.
func (w *Wallet) requireDraft13() error {
	if !w.draft13 {
		return fmt.Errorf("%w: Config.Profiles does not enable profile.Draft13", ErrProfileForbidsDraft)
	}
	return nil
}

// requireDraft24 refuses an OpenID4VP Draft 24 entry point unless
// Config.Profiles enables profile.Draft24.
func (w *Wallet) requireDraft24() error {
	if !w.draft24 {
		return fmt.Errorf("%w: Config.Profiles does not enable profile.Draft24", ErrProfileForbidsDraft)
	}
	return nil
}

// validatesCredentialConfigurations reports whether o constrains a Credential
// Configuration, which the OpenID4VCI receiver then validates.
func validatesCredentialConfigurations(o profile.Options) bool {
	return o.RequireIssuerMetadataScopes || o.AllowedCredentialFormats != 0
}
