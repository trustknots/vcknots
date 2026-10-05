package profile

import (
	"fmt"
	"slices"
	"strings"

	"github.com/trustknots/vcknots/wallet/common"
)

// ErrOptionsConflict reports Options that together admit no input, which
// Profile.With refuses (see ConflictError).
var ErrOptionsConflict = common.NewCodedError("profile_options_conflict", "the profile options admit no input")

// ConflictError reports Options that together admit no input: two restrictions
// of one set with no member in common, or a combination of options that
// refuses every request of a flow. errors.Is(err, ErrOptionsConflict) holds.
type ConflictError struct {
	// Options are the names of the conflicting options, as Options.String
	// spells them.
	Options []string
	// Reason says why no input satisfies them.
	Reason string
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("%s: %s: %s", ErrOptionsConflict, strings.Join(e.Options, " with "), e.Reason)
}

// Unwrap returns ErrOptionsConflict.
func (e *ConflictError) Unwrap() error { return ErrOptionsConflict }

// OptionError names the profile option that refused an input. The library
// puts one in the chain of every error an option causes, next to the error
// that classifies the refusal, so errors.As tells which option refused
// whatever the error's code:
//
//	var refused *profile.OptionError
//	if errors.As(err, &refused) {
//		log.Printf("refused by %s", refused.Option)
//	}
//
// OptionError carries no code of its own, so common.CodeOf still reports the
// classifying error.
type OptionError struct {
	// Option is the option's name as Options.String spells it, such as
	// "RequireDPoP" or "IssuerX5C.Require".
	Option string
}

func (e *OptionError) Error() string { return "profile option " + e.Option }

// Refused returns the *OptionError naming option, for a message such as
// fmt.Errorf("%w requires ...: %w", profile.Refused("RequireDPoP"), cause).
func Refused(option string) error {
	return &OptionError{Option: option}
}

// Covers reports whether o keeps every option of floor at least as strict.
// Options().Covers(HAIPOptions()) tells a profile that enforces at least all
// of HAIP 1.0.
func (o Options) Covers(floor Options) bool {
	return len(o.weakened(floor)) == 0
}

// String names the options that are on, joined with ";", in the spelling of
// the text form of a Profile, or "none" for the zero Options.
func (o Options) String() string {
	elements := o.elements(Options{})
	if len(elements) == 0 {
		return "none"
	}
	return strings.Join(elements, optionSeparator)
}

// optionSeparator joins the elements of the text form of a Profile. It is not
// "+", which occurs in the Credential Format Identifier dc+sd-jwt.
const optionSeparator = ";"

// option describes one option of Options: a flag, or a set whose zero value
// restricts nothing. The list below is in field order and is the single
// place that names an option; the tests check it covers every field.
type option struct {
	name string
	// flag returns the field of a flag option.
	flag func(*Options) *bool
	// get and put read and write the field of a set option, whose members
	// are named by members, bit by bit.
	get     func(Options) uint16
	put     func(*Options, uint16)
	members []string
}

func flagOption(name string, field func(*Options) *bool) option {
	return option{name: name, flag: field}
}

func x5cOptions(name string, field func(*Options) *X5CRules) []option {
	return []option{
		flagOption(name+".Require", func(o *Options) *bool { return &field(o).Require }),
		flagOption(name+".ExcludeAnchor", func(o *Options) *bool { return &field(o).ExcludeAnchor }),
		flagOption(name+".RejectSelfSigned", func(o *Options) *bool { return &field(o).RejectSelfSigned }),
	}
}

var options = func() []option {
	list := []option{
		flagOption("ForbidExperimental", func(o *Options) *bool { return &o.ForbidExperimental }),
		flagOption("ForbidDraftProfiles", func(o *Options) *bool { return &o.ForbidDraftProfiles }),
		{
			name:    "AllowedCredentialFormats",
			get:     func(o Options) uint16 { return uint16(o.AllowedCredentialFormats) },
			put:     func(o *Options, v uint16) { o.AllowedCredentialFormats = CredentialFormats(v) },
			members: credentialFormatNames,
		},
	}
	list = append(list, x5cOptions("IssuerX5C", func(o *Options) *X5CRules { return &o.IssuerX5C })...)
	list = append(list, x5cOptions("StatusListTokenX5C", func(o *Options) *X5CRules { return &o.StatusListTokenX5C })...)
	list = append(list, flagOption("RequireStatusListSignerBinding", func(o *Options) *bool { return &o.RequireStatusListSignerBinding }))
	list = append(list,
		flagOption("RequirePAR", func(o *Options) *bool { return &o.RequirePAR }),
		flagOption("RequireDPoP", func(o *Options) *bool { return &o.RequireDPoP }),
		flagOption("RequireAuthorizationResponseIss", func(o *Options) *bool { return &o.RequireAuthorizationResponseIss }),
		flagOption("RequireScopeAuthorization", func(o *Options) *bool { return &o.RequireScopeAuthorization }),
		flagOption("RequireIssuerMetadataScopes", func(o *Options) *bool { return &o.RequireIssuerMetadataScopes }),
		flagOption("RequireNonceEndpointForKeyBinding", func(o *Options) *bool { return &o.RequireNonceEndpointForKeyBinding }),
		flagOption("RequestSignedIssuerMetadata", func(o *Options) *bool { return &o.RequestSignedIssuerMetadata }),
	)
	list = append(list, x5cOptions("SignedMetadataX5C", func(o *Options) *X5CRules { return &o.SignedMetadataX5C })...)
	list = append(list, flagOption("RequireClientAuthentication", func(o *Options) *bool { return &o.RequireClientAuthentication }))
	list = append(list, x5cOptions("AttestationX5C", func(o *Options) *X5CRules { return &o.AttestationX5C })...)
	list = append(list,
		flagOption("RequireSignedRequestByReference", func(o *Options) *bool { return &o.RequireSignedRequestByReference }),
		flagOption("RequireDirectPostJWT", func(o *Options) *bool { return &o.RequireDirectPostJWT }),
		flagOption("RequireDCAPIJWT", func(o *Options) *bool { return &o.RequireDCAPIJWT }),
		option{
			name:    "AllowedClientIDPrefixes",
			get:     func(o Options) uint16 { return uint16(o.AllowedClientIDPrefixes) },
			put:     func(o *Options, v uint16) { o.AllowedClientIDPrefixes = ClientIDPrefixes(v) },
			members: clientIDPrefixNames,
		},
	)
	list = append(list, x5cOptions("RequestObjectX5C", func(o *Options) *X5CRules { return &o.RequestObjectX5C })...)
	list = append(list,
		flagOption("ResponseEncryption.ECDHESOnly", func(o *Options) *bool { return &o.ResponseEncryption.ECDHESOnly }),
		flagOption("ResponseEncryption.P256Only", func(o *Options) *bool { return &o.ResponseEncryption.P256Only }),
		flagOption("ResponseEncryption.GCMOnly", func(o *Options) *bool { return &o.ResponseEncryption.GCMOnly }),
		flagOption("ResponseEncryption.RequireVerifierGCMBoth", func(o *Options) *bool { return &o.ResponseEncryption.RequireVerifierGCMBoth }),
		flagOption("AlwaysKeyBindingWhenConfirmed", func(o *Options) *bool { return &o.AlwaysKeyBindingWhenConfirmed }),
	)
	return list
}()

// merge returns the options o or p turns on: a flag on in either, and a set
// restricted to the members both allow. Two restrictions of a set with no
// member in common conflict.
func (o Options) merge(p Options) (Options, error) {
	merged := o
	for _, opt := range options {
		if opt.flag != nil {
			*opt.flag(&merged) = *opt.flag(&o) || *opt.flag(&p)
			continue
		}
		a, b := opt.get(o), opt.get(p)
		switch {
		case a == 0:
			opt.put(&merged, b)
		case b == 0:
			opt.put(&merged, a)
		case a&b == 0:
			return Options{}, &ConflictError{
				Options: []string{opt.name},
				Reason:  fmt.Sprintf("%s and %s have no member in common", setString(a, opt.members), setString(b, opt.members)),
			}
		default:
			opt.put(&merged, a&b)
		}
	}
	return merged, nil
}

// signedRequestPrefixes are the Client Identifier Prefixes of a request a
// Wallet can authenticate from the x5c header of a signed Request Object.
const signedRequestPrefixes = ClientIDPrefixX509SanDNS | ClientIDPrefixX509Hash

// validate refuses combinations that refuse every request of a flow.
func (o Options) validate() error {
	prefixes := o.AllowedClientIDPrefixes
	if !o.RequireSignedRequestByReference || prefixes == 0 {
		return nil
	}
	if prefixes&^(ClientIDPrefixRedirectURI|ClientIDPrefixOrigin) == 0 {
		return &ConflictError{
			Options: []string{"RequireSignedRequestByReference", "AllowedClientIDPrefixes"},
			Reason: "a redirect_uri request cannot be signed (OpenID4VP 1.0 §5.9.3) and a Wallet accepts no origin request, " +
				"so every redirect-based request would be refused",
		}
	}
	if o.RequestObjectX5C.Require && prefixes&signedRequestPrefixes == 0 {
		return &ConflictError{
			Options: []string{"RequireSignedRequestByReference", "RequestObjectX5C.Require", "AllowedClientIDPrefixes"},
			Reason:  "a redirect-based request must be signed with x5c, which only an x509_san_dns or x509_hash request carries",
		}
	}
	return nil
}

// weakened names the options of floor that o does not keep at least as
// strict.
func (o Options) weakened(floor Options) []string {
	var names []string
	for _, opt := range options {
		if opt.flag != nil {
			if *opt.flag(&floor) && !*opt.flag(&o) {
				names = append(names, opt.name)
			}
			continue
		}
		got, want := opt.get(o), opt.get(floor)
		if want != 0 && (got == 0 || got&^want != 0) {
			names = append(names, opt.name)
		}
	}
	return names
}

// elements are the text form elements of the options o applies beyond base,
// which o covers: each flag o turns on and base does not, and each set o
// restricts differently from base.
func (o Options) elements(base Options) []string {
	var elements []string
	for _, opt := range options {
		if opt.flag != nil {
			if *opt.flag(&o) && !*opt.flag(&base) {
				elements = append(elements, opt.name)
			}
			continue
		}
		if value := opt.get(o); value != opt.get(base) {
			elements = append(elements, opt.name+"="+setString(value, opt.members))
		}
	}
	return elements
}

// parseOptionElements returns the Options the text form elements name.
func parseOptionElements(elements []string) (Options, error) {
	var parsed Options
	for _, element := range elements {
		name, value, isSet := strings.Cut(element, "=")
		one, err := parseOptionElement(name, value, isSet)
		if err != nil {
			return Options{}, err
		}
		if parsed, err = parsed.merge(one); err != nil {
			return Options{}, err
		}
	}
	return parsed, nil
}

func parseOptionElement(name, value string, isSet bool) (Options, error) {
	var one Options
	for _, opt := range options {
		if opt.name != name {
			continue
		}
		if opt.flag != nil {
			if isSet {
				return Options{}, fmt.Errorf("%w: the option %s takes no value", ErrUnknownProfile, name)
			}
			*opt.flag(&one) = true
			return one, nil
		}
		bits, err := parseSet(value, opt.members)
		if !isSet || err != nil {
			return Options{}, fmt.Errorf("%w: the option %s needs %s=member[,member...]: %v", ErrUnknownProfile, name, name, err)
		}
		opt.put(&one, bits)
		return one, nil
	}
	return Options{}, fmt.Errorf("%w: unknown option %q", ErrUnknownProfile, name)
}

func parseSet(value string, members []string) (uint16, error) {
	var bits uint16
	for _, member := range strings.Split(value, ",") {
		index := slices.Index(members, member)
		if index < 0 {
			return 0, fmt.Errorf("unknown member %q", member)
		}
		bits |= 1 << index
	}
	return bits, nil
}
