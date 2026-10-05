// Package profile names the protocol profiles a wallet runs.
//
// A Profile is a protocol Version and the Options the wallet applies on top of
// it. VersionFinal is OpenID4VCI 1.0 and OpenID4VP 1.0; the draft versions
// (VersionDraft13 for OpenID4VCI Draft 13, VersionDraft24 for OpenID4VP Draft
// 24) take no options. HAIP 1.0 is not a version of its own: it is a set of
// constraints on the 1.0 specifications, so HAIP() is VersionFinal with
// HAIPOptions(), and equals Final().With(HAIPOptions()).
//
// Profiles are comparable values: two Profiles apply the same rules exactly
// when they are ==, however they were built. The zero Profile is Final().
//
// A Profile has a text form (String, MarshalText, ParseProfile) that
// round-trips its Options, so a Profile can cross a process boundary or be
// stored in a flow state without losing a constraint:
//
//	final                     Final()
//	haip                      HAIP()
//	draft13, draft24          Draft13(), Draft24()
//	final;RequireDPoP;RequirePAR
//	                          Final().With(Options{RequireDPoP: true, RequirePAR: true})
//	haip;AllowedCredentialFormats=mso_mdoc
//	                          HAIP() restricted to mso_mdoc
//
// The first element is a version name or "haip"; each further element, joined
// with ";", names one option as the Options field spells it (a nested rule as
// "IssuerX5C.Require", a set as "Name=member,member").
package profile

import (
	"fmt"
	"strings"

	"github.com/trustknots/vcknots/wallet/common"
)

// Version is a protocol version a Profile runs.
type Version uint8

const (
	// VersionFinal is OpenID4VCI 1.0 and OpenID4VP 1.0. It is the zero
	// Version.
	VersionFinal Version = iota
	// VersionDraft13 is OpenID4VCI Draft 13 issuance.
	VersionDraft13
	// VersionDraft24 is OpenID4VP Draft 24 presentation.
	VersionDraft24
)

var versionNames = [...]string{VersionFinal: "final", VersionDraft13: "draft13", VersionDraft24: "draft24"}

// String names v as the text form of a Profile does: "final", "draft13" or
// "draft24".
func (v Version) String() string {
	if int(v) < len(versionNames) {
		return versionNames[v]
	}
	return fmt.Sprintf("Version(%d)", uint8(v))
}

// haipName is the text form of HAIP(): VersionFinal with exactly
// HAIPOptions(). It names a preset, not a version.
const haipName = "haip"

// Profile is a protocol profile: a Version and the Options applied on top of
// it. The zero value is Final().
type Profile struct {
	version Version
	options Options
}

var (
	// ErrDraftProfile reports a draft profile where an OpenID4VCI 1.0 /
	// OpenID4VP 1.0 profile is required, or options given to a draft profile.
	ErrDraftProfile = common.NewCodedError("draft_profile", "a draft profile is not an OpenID4VCI 1.0 / OpenID4VP 1.0 profile")
	// ErrUnknownProfile reports a text that is not the text form of a
	// Profile: an unknown version name or option, or a malformed element.
	ErrUnknownProfile = common.NewCodedError("profile_unknown", "not a profile")
)

// Final is OpenID4VCI 1.0 and OpenID4VP 1.0 with no additional constraint.
func Final() Profile {
	return Profile{}
}

// HAIP is HAIP 1.0 (OpenID4VC High Assurance Interoperability Profile):
// VersionFinal with HAIPOptions. It equals Final().With(HAIPOptions()).
func HAIP() Profile {
	return Profile{options: HAIPOptions()}
}

// Draft13 is OpenID4VCI Draft 13 issuance.
func Draft13() Profile {
	return Profile{version: VersionDraft13}
}

// Draft24 is OpenID4VP Draft 24 presentation.
func Draft24() Profile {
	return Profile{version: VersionDraft24}
}

// Version reports the protocol version p runs.
func (p Profile) Version() Version {
	return p.version
}

// Draft reports whether p runs a draft protocol version (Draft13 or
// Draft24).
func (p Profile) Draft() bool {
	return p.version != VersionFinal
}

// Options returns the constraints p applies. A draft profile has none.
func (p Profile) Options() Options {
	return p.options
}

// With returns p with o added to its options. It only strengthens: a flag on
// in either p or o is on in the result, and a set restricts to the members
// both allow, so no option p carries can be weakened, and With chains:
// Final().With(a).With(b) applies both a and b. Final().With(HAIPOptions())
// equals HAIP().
//
// With fails with a *ConflictError (ErrOptionsConflict) when the result
// admits no input at all - two sets with no member in common, or a
// combination that refuses every request - and with ErrDraftProfile when p
// is a draft profile and o is not the zero Options.
func (p Profile) With(o Options) (Profile, error) {
	if p.Draft() {
		if o == (Options{}) {
			return p, nil
		}
		return p, fmt.Errorf("%w: %s takes no options", ErrDraftProfile, p.version)
	}
	merged, err := p.options.merge(o)
	if err != nil {
		return p, err
	}
	if err := merged.validate(); err != nil {
		return p, err
	}
	return Profile{version: p.version, options: merged}, nil
}

// RequireFinalVersion returns ErrDraftProfile when p is a draft profile, for
// a plugin field that takes an OpenID4VCI 1.0 / OpenID4VP 1.0 profile.
func (p Profile) RequireFinalVersion() error {
	if p.Draft() {
		return fmt.Errorf("%w: %s", ErrDraftProfile, p.version)
	}
	return nil
}

// String returns the text form of p, which names every option p applies
// (see the package documentation). ParseProfile(p.String()) == p.
func (p Profile) String() string {
	if p.options == (Options{}) {
		return p.version.String()
	}
	if p.options == HAIPOptions() {
		return haipName
	}
	base, baseOptions := p.version.String(), Options{}
	if p.options.Covers(HAIPOptions()) {
		base, baseOptions = haipName, HAIPOptions()
	}
	elements := append([]string{base}, p.options.elements(baseOptions)...)
	return strings.Join(elements, optionSeparator)
}

// MarshalText encodes p as its text form, so encoding/json writes a Profile
// as a string that keeps its Options.
func (p Profile) MarshalText() ([]byte, error) {
	return []byte(p.String()), nil
}

// UnmarshalText decodes the text form of a Profile (ParseProfile).
func (p *Profile) UnmarshalText(text []byte) error {
	parsed, err := ParseProfile(string(text))
	if err != nil {
		return err
	}
	*p = parsed
	return nil
}

// ParseProfile returns the Profile whose text form is text: "final",
// "haip", "draft13" or "draft24", optionally followed by options (see the
// package documentation). The options are added with With, so a text that
// names contradictory options fails as With does. An empty or unknown text
// fails with ErrUnknownProfile.
func ParseProfile(text string) (Profile, error) {
	elements := strings.Split(text, optionSeparator)
	var base Profile
	switch elements[0] {
	case VersionFinal.String():
		base = Final()
	case haipName:
		base = HAIP()
	case VersionDraft13.String():
		base = Draft13()
	case VersionDraft24.String():
		base = Draft24()
	default:
		return Profile{}, fmt.Errorf("%w: %q: want final, haip, draft13 or draft24, optionally followed by options", ErrUnknownProfile, text)
	}
	options, err := parseOptionElements(elements[1:])
	if err != nil {
		return Profile{}, fmt.Errorf("%q: %w", text, err)
	}
	return base.With(options)
}

// Carrier is implemented by protocol plugins that report the OpenID4VCI 1.0
// / OpenID4VP 1.0 profile they enforce. The wallet refuses a plugin whose
// profile differs from its own and, when its profile carries any option, a
// plugin that is not a Carrier, since it would not apply those options.
type Carrier interface {
	ProtocolProfile() Profile
}
