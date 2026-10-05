package wallet

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/experimental"
	"github.com/trustknots/vcknots/wallet/profile"
	"github.com/trustknots/vcknots/wallet/receiver"
	"github.com/trustknots/vcknots/wallet/receiver/plugins/mock"
	"github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

func TestConfigProfilesDefaultEnablesFinalAndBothDrafts(t *testing.T) {
	w, err := NewWalletWithConfig(Config{Storeless: true})
	require.NoError(t, err)
	require.Equal(t, profile.Final(), w.profile)
	require.True(t, w.draft13)
	require.True(t, w.draft24)
	require.Equal(t, []profile.Profile{profile.Final(), profile.Draft13(), profile.Draft24()}, DefaultProfiles())
}

func TestConfigProfilesRefusesInvalidSets(t *testing.T) {
	strengthened, err := profile.Final().With(profile.Options{RequirePAR: true})
	require.NoError(t, err)
	for name, test := range map[string]struct {
		profiles []profile.Profile
		want     error
	}{
		"HAIP with Draft 13":        {[]profile.Profile{profile.HAIP(), profile.Draft13()}, ErrProfileForbidsDraft},
		"HAIP with Draft 24":        {[]profile.Profile{profile.Draft24(), profile.HAIP()}, ErrProfileForbidsDraft},
		"no 1.0 profile":            {[]profile.Profile{profile.Draft13(), profile.Draft24()}, ErrInvalidArgument},
		"two 1.0 profiles":          {[]profile.Profile{profile.Final(), strengthened}, ErrInvalidArgument},
		"a draft profile twice":     {[]profile.Profile{profile.Final(), profile.Draft13(), profile.Draft13()}, ErrInvalidArgument},
		"Final and HAIP both named": {[]profile.Profile{profile.Final(), profile.HAIP()}, ErrInvalidArgument},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewWalletWithConfig(Config{Profiles: test.profiles, Storeless: true})
			requireCoded(t, err, test.want)
		})
	}
}

// The draft refusal must not depend on the profile's name, or
// profile.Final().With(profile.HAIPOptions()) would run beside Draft 13, Draft
// 24 and Experimental.Hooks, nor be inferred from "covers all of HAIPOptions",
// or dropping any one HAIP option would re-enable the drafts. The refusal is
// the explicit option ForbidDraftProfiles (HAIP 1.0 §1: the base protocols are
// OpenID4VCI 1.0 and OpenID4VP 1.0), and Experimental.Hooks falls under
// ForbidExperimental.
func TestConfigProfilesRefuseDraftsUnderForbidDraftProfiles(t *testing.T) {
	strict, err := profile.Final().With(profile.HAIPOptions())
	require.NoError(t, err)
	onlyFinal, err := profile.Final().With(profile.Options{ForbidDraftProfiles: true})
	require.NoError(t, err)
	for _, p := range []profile.Profile{profile.HAIP(), strict, onlyFinal} {
		for name, profiles := range map[string][]profile.Profile{
			"Draft 13": {p, profile.Draft13()},
			"Draft 24": {profile.Draft24(), p},
			"both":     {p, profile.Draft13(), profile.Draft24()},
		} {
			t.Run(p.String()+" with "+name, func(t *testing.T) {
				_, err := NewWalletWithConfig(Config{Profiles: profiles, Storeless: true})
				requireCoded(t, err, ErrProfileForbidsDraft)
				requireRefusedBy(t, err, "ForbidDraftProfiles")
			})
		}
	}

	// Every other HAIP option leaves the drafts to the caller.
	withoutForbid := profile.HAIPOptions()
	withoutForbid.ForbidDraftProfiles = false
	rest, err := profile.Final().With(withoutForbid)
	require.NoError(t, err)
	_, err = NewWalletWithConfig(Config{Profiles: []profile.Profile{rest, profile.Draft13(), profile.Draft24()}, Storeless: true})
	require.NoError(t, err)
}

func TestConfigExperimentalRefusedUnderForbidExperimental(t *testing.T) {
	hooks := experimental.Options{Hooks: experimental.Hooks{KeyProof: experimental.ProofTransform{Serialized: identityProof}}}
	transport := experimental.Options{Transport: experimental.Transport{AllowHTTP: true}}
	forbid, err := profile.Final().With(profile.Options{ForbidExperimental: true})
	require.NoError(t, err)
	for _, p := range []profile.Profile{profile.HAIP(), forbid} {
		for name, settings := range map[string]experimental.Options{"Hooks": hooks, "Transport": transport} {
			t.Run(p.String()+" with "+name, func(t *testing.T) {
				profiles := []profile.Profile{p}
				if !p.Options().ForbidDraftProfiles {
					profiles = append(profiles, profile.Draft13())
				}
				_, err := NewWalletWithConfig(Config{Profiles: profiles, Storeless: true, Experimental: settings})
				requireCoded(t, err, ErrInvalidArgument)
				requireRefusedBy(t, err, "ForbidExperimental")
			})
		}
	}
}

// requireRefusedBy asserts that err names option as the profile option that
// refused.
func requireRefusedBy(t *testing.T, err error, option string) {
	t.Helper()
	var refused *profile.OptionError
	require.ErrorAs(t, err, &refused)
	require.Equal(t, option, refused.Option)
}

// A HAIP() plugin is accepted in a wallet built with
// Final().With(HAIPOptions()) rather than refused with ErrProfileMismatch:
// plugin profiles compare by version and options.
func TestPluginProfilesCompareVersionAndOptions(t *testing.T) {
	strict, err := profile.Final().With(profile.HAIPOptions())
	require.NoError(t, err)
	receiver, err := receiver.NewReceivingDispatcher(receiver.WithPlugin(receiverTypes.Oid4vci, &oid4vci.Oid4vciReceiver{Profile: profile.HAIP()}))
	require.NoError(t, err)
	_, err = NewWalletWithConfig(Config{Profiles: []profile.Profile{strict}, Receiver: receiver, Storeless: true})
	require.NoError(t, err)

	partial, err := profile.Final().With(profile.Options{RequireDPoP: true})
	require.NoError(t, err)
	_, err = NewWalletWithConfig(Config{Profiles: []profile.Profile{partial}, Receiver: receiver, Storeless: true})
	requireCoded(t, err, ErrProfileMismatch)
}

func TestConfigProfilesAcceptsStrengthenedFinalWithDrafts(t *testing.T) {
	strengthened, err := profile.Final().With(profile.Options{RequireDPoP: true, RequirePAR: true})
	require.NoError(t, err)
	w, err := NewWalletWithConfig(Config{Profiles: []profile.Profile{strengthened, profile.Draft13()}, Storeless: true})
	require.NoError(t, err)
	require.Equal(t, strengthened, w.profile)
	require.True(t, w.draft13)
	require.False(t, w.draft24)
	// The default receiver carries the strengthened profile.
	plugins := w.receiver.Plugins()
	require.Len(t, plugins, 1)
	require.Equal(t, strengthened, plugins[0].(profile.Carrier).ProtocolProfile())
}

func TestConfigProfilesWithOptionsRefusesPluginsWithoutProfile(t *testing.T) {
	strengthened, err := profile.Final().With(profile.Options{RequireDPoP: true})
	require.NoError(t, err)
	_, err = NewWalletWithConfig(Config{
		Profiles: []profile.Profile{strengthened},
		Receiver: receiverWith(t, mock.NewMockReceiver(t.TempDir())), Storeless: true,
	})
	requireCoded(t, err, ErrProfilePluginUnsupported)
}

func TestDraftEntryPointsNeedTheirDraftProfile(t *testing.T) {
	finalOnly, err := NewWalletWithConfig(Config{Profiles: []profile.Profile{profile.Final()}, Storeless: true})
	require.NoError(t, err)

	_, err = finalOnly.Draft13().RequestCredential(t.Context(), &IssuanceGrant{}, CredentialRequest{})
	requireCoded(t, err, ErrProfileForbidsDraft)
	_, err = finalOnly.Draft13().BeginIssuance(t.Context(), IssuanceRequest{})
	requireCoded(t, err, ErrProfileForbidsDraft)
	err = finalOnly.Draft13().NotifyIssuer(t.Context(), &IssuanceNotification{}, NotificationEvent("credential_accepted"), "")
	requireCoded(t, err, ErrProfileForbidsDraft)
	_, err = finalOnly.Draft13().AuthorizePreAuthorizedIssuance(t.Context(), PreAuthorizedIssuanceRequest{})
	requireCoded(t, err, ErrProfileForbidsDraft)
	_, err = finalOnly.Draft24().ParsePresentationRequest(t.Context(), "openid4vp://?client_id=x")
	requireCoded(t, err, ErrProfileForbidsDraft)

	// Each draft profile enables only its own entry points.
	vp24Only, err := NewWalletWithConfig(Config{Profiles: []profile.Profile{profile.Final(), profile.Draft24()}, Storeless: true})
	require.NoError(t, err)
	_, err = vp24Only.Draft13().RequestCredential(t.Context(), &IssuanceGrant{}, CredentialRequest{})
	requireCoded(t, err, ErrProfileForbidsDraft)
	_, err = vp24Only.Draft24().ParsePresentationRequest(t.Context(), "openid4vp://?client_id=x")
	require.NotErrorIs(t, err, ErrProfileForbidsDraft)
}

func TestExperimentalHooksNeedADraftProfile(t *testing.T) {
	_, err := NewWalletWithConfig(Config{Profiles: []profile.Profile{profile.Final()}, Storeless: true, Experimental: experimental.Options{Hooks: experimental.Hooks{KeyProof: experimental.ProofTransform{Serialized: identityProof}}}})
	requireCoded(t, err, ErrProfileForbidsDraft)
	_, err = NewWalletWithConfig(Config{Profiles: []profile.Profile{profile.Final(), profile.Draft13()}, Storeless: true, Experimental: experimental.Options{Hooks: experimental.Hooks{KeyProof: experimental.ProofTransform{Serialized: identityProof}}}})
	require.NoError(t, err)
}

// identityProof is a key proof hook that changes nothing, so a test can set
// Experimental.Hooks without altering a message.
func identityProof(proof string) (string, error) { return proof, nil }
