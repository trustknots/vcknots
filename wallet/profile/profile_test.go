package profile

import (
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"testing"

	"github.com/trustknots/vcknots/wallet/common"
)

func TestZeroProfileIsFinal(t *testing.T) {
	if (Profile{}) != Final() {
		t.Fatal("the zero Profile must be Final()")
	}
	if Final().Options() != (Options{}) {
		t.Fatal("Final must carry no option")
	}
}

// leafFields visits every bool leaf and every set of Options, so a field
// added to Options is covered by the tests below without editing them.
func leafFields(t *testing.T, visit func(path string, field reflect.Value)) {
	t.Helper()
	var walk func(path string, value reflect.Value)
	walk = func(path string, value reflect.Value) {
		switch value.Kind() {
		case reflect.Struct:
			for index := 0; index < value.NumField(); index++ {
				name := value.Type().Field(index).Name
				if path != "" {
					name = path + "." + name
				}
				walk(name, value.Field(index))
			}
		case reflect.Bool, reflect.Uint8, reflect.Uint16:
			visit(path, value)
		default:
			t.Fatalf("Options field %s has unexpected kind %s", path, value.Kind())
		}
	}
	var options Options
	walk("", reflect.ValueOf(&options).Elem())
}

// walletChoices are the options that state a check the specifications leave
// to the Wallet rather than a requirement of HAIP 1.0, so HAIPOptions leaves
// them off.
var walletChoices = map[string]bool{
	// draft-ietf-oauth-status-list-21 §11.3 mandates no signer binding, and
	// HAIP 1.0 §6.1 adds none.
	"RequireStatusListSignerBinding": true,
}

func TestHAIPOptionsTurnsOnEveryRequirement(t *testing.T) {
	haip := reflect.ValueOf(HAIPOptions())
	leafFields(t, func(path string, _ reflect.Value) {
		field := haip.FieldByIndex(fieldIndex(t, path))
		if walletChoices[path] {
			if !field.IsZero() {
				t.Errorf("HAIPOptions turns on %s, which HAIP does not require", path)
			}
			return
		}
		if field.IsZero() {
			t.Errorf("HAIPOptions leaves %s off", path)
		}
	})
	options := HAIPOptions()
	if options.AllowedCredentialFormats != FormatSDJWTVC|FormatMsoMdoc {
		t.Errorf("AllowedCredentialFormats = %s", options.AllowedCredentialFormats)
	}
	if options.AllowedClientIDPrefixes != ClientIDPrefixX509Hash {
		t.Errorf("AllowedClientIDPrefixes = %s", options.AllowedClientIDPrefixes)
	}
	if HAIP().Options() != options {
		t.Fatal("HAIP() must carry HAIPOptions()")
	}
}

func fieldIndex(t *testing.T, path string) []int {
	t.Helper()
	var index []int
	typ := reflect.TypeOf(Options{})
	for _, name := range splitPath(path) {
		field, ok := typ.FieldByName(name)
		if !ok {
			t.Fatalf("no field %s", path)
		}
		index = append(index, field.Index...)
		typ = field.Type
	}
	return index
}

func splitPath(path string) []string {
	var parts []string
	start := 0
	for index := 0; index < len(path); index++ {
		if path[index] == '.' {
			parts = append(parts, path[start:index])
			start = index + 1
		}
	}
	return append(parts, path[start:])
}

func TestDraftProfilesTakeNoOptions(t *testing.T) {
	for _, draft := range []Profile{Draft13(), Draft24()} {
		if _, err := draft.With(Options{RequireDPoP: true}); !errors.Is(err, ErrDraftProfile) {
			t.Errorf("%s.With: error = %v, want ErrDraftProfile", draft, err)
		}
		if same, err := draft.With(Options{}); err != nil || same != draft {
			t.Errorf("%s.With(zero) = %v, %v", draft, same, err)
		}
		if err := draft.RequireFinalVersion(); !errors.Is(err, ErrDraftProfile) {
			t.Errorf("%s.RequireFinalVersion = %v", draft, err)
		}
	}
	if err := HAIP().RequireFinalVersion(); err != nil {
		t.Fatal(err)
	}
}

func TestSets(t *testing.T) {
	var any CredentialFormats
	if !any.Allows("jwt_vc_json") || !any.Allows("unknown") {
		t.Fatal("the empty set allows every format")
	}
	haip := HAIPOptions().AllowedCredentialFormats
	if !haip.Allows("dc+sd-jwt") || !haip.Allows("mso_mdoc") || haip.Allows("jwt_vc_json") || haip.Allows("vc+sd-jwt") {
		t.Fatalf("HAIP formats %s", haip)
	}
	prefixes := HAIPOptions().AllowedClientIDPrefixes
	if !prefixes.Allows("x509_hash") || prefixes.Allows("x509_san_dns") || prefixes.Allows("bogus") {
		t.Fatalf("HAIP prefixes %s", prefixes)
	}
	if (ClientIDPrefixes(0)).String() != "any" || haip.String() != "dc+sd-jwt,mso_mdoc" {
		t.Fatal("String")
	}
}

func TestVersions(t *testing.T) {
	tests := []struct {
		profile Profile
		version Version
		text    string
	}{
		{Final(), VersionFinal, "final"},
		{HAIP(), VersionFinal, "haip"},
		{Draft13(), VersionDraft13, "draft13"},
		{Draft24(), VersionDraft24, "draft24"},
	}
	for _, tt := range tests {
		if got := tt.profile.Version(); got != tt.version {
			t.Errorf("%s: Version() = %s, want %s", tt.text, got, tt.version)
		}
		if got := tt.profile.String(); got != tt.text {
			t.Errorf("String() = %q, want %q", got, tt.text)
		}
		if got := tt.profile.Draft(); got != (tt.version != VersionFinal) {
			t.Errorf("%s: Draft() = %v", tt.text, got)
		}
	}
}

// HAIP() is Final().With(HAIPOptions()): no kind label of its own separates
// a plugin built with one from a wallet built with the other, as both apply
// the same rules.
func TestHAIPIsFinalWithHAIPOptions(t *testing.T) {
	built, err := Final().With(HAIPOptions())
	if err != nil {
		t.Fatal(err)
	}
	if built != HAIP() {
		t.Fatalf("Final().With(HAIPOptions()) = %s, want HAIP()", built)
	}
	if built.String() != "haip" || built.Version() != VersionFinal {
		t.Fatalf("String/Version = %q/%s", built.String(), built.Version())
	}
}

// With strengthens the options it is given, so Final().With(a).With(b)
// succeeds without b repeating a.
func TestWithComposesByStrengthening(t *testing.T) {
	chained, err := Final().With(Options{RequireDPoP: true})
	if err != nil {
		t.Fatal(err)
	}
	chained, err = chained.With(Options{RequirePAR: true, AllowedCredentialFormats: FormatSDJWTVC | FormatJWTVCJSON})
	if err != nil {
		t.Fatal(err)
	}
	chained, err = chained.With(Options{AllowedCredentialFormats: FormatSDJWTVC | FormatMsoMdoc})
	if err != nil {
		t.Fatal(err)
	}
	want := Options{RequireDPoP: true, RequirePAR: true, AllowedCredentialFormats: FormatSDJWTVC}
	if chained.Options() != want {
		t.Fatalf("chained options = %s, want %s", chained.Options(), want)
	}
	// Composition is order-independent.
	reversed, err := Final().With(Options{AllowedCredentialFormats: FormatSDJWTVC | FormatMsoMdoc})
	if err != nil {
		t.Fatal(err)
	}
	if reversed, err = reversed.With(want); err != nil || reversed != chained {
		t.Fatalf("reversed = %s, %v; want %s", reversed, err, chained)
	}
}

func TestWithNeverWeakensAnOption(t *testing.T) {
	leafFields(t, func(path string, _ reflect.Value) {
		weakened := HAIPOptions()
		field := reflect.ValueOf(&weakened).Elem().FieldByIndex(fieldIndex(t, path))
		field.Set(reflect.Zero(field.Type()))
		got, err := HAIP().With(weakened)
		if err != nil || got != HAIP() {
			t.Errorf("HAIP().With(HAIPOptions() without %s) = %s, %v; want HAIP()", path, got, err)
		}
	})
	widened := HAIPOptions()
	widened.AllowedCredentialFormats |= FormatJWTVCJSON
	widened.AllowedClientIDPrefixes |= ClientIDPrefixX509SanDNS
	if got, err := HAIP().With(widened); err != nil || got != HAIP() {
		t.Fatalf("HAIP().With(widened sets) = %s, %v", got, err)
	}
}

func TestWithRefusesSetsWithNoCommonMember(t *testing.T) {
	_, err := HAIP().With(Options{AllowedCredentialFormats: FormatJWTVCJSON})
	var conflict *ConflictError
	if !errors.As(err, &conflict) || !slices.Equal(conflict.Options, []string{"AllowedCredentialFormats"}) {
		t.Fatalf("error = %v, want a ConflictError naming AllowedCredentialFormats", err)
	}
	if code, ok := common.CodeOf(err); !ok || code != "profile_options_conflict" || !errors.Is(err, ErrOptionsConflict) {
		t.Fatalf("CodeOf = %q, %v", code, ok)
	}
	if _, err := Final().With(Options{AllowedClientIDPrefixes: ClientIDPrefixX509Hash}); err != nil {
		t.Fatal(err)
	}
}

// OpenID4VP 1.0 §5.9.3: "Requests using the redirect_uri Client Identifier
// Prefix cannot be signed", and "The Wallet MUST NOT accept" the origin
// prefix in requests. With refuses these combinations up front rather than
// letting them refuse every request at run time.
func TestWithRefusesOptionsThatRefuseEveryRedirectRequest(t *testing.T) {
	tests := map[string]struct {
		options Options
		names   []string
	}{
		"signed by reference with redirect_uri only": {
			Options{RequireSignedRequestByReference: true, AllowedClientIDPrefixes: ClientIDPrefixRedirectURI | ClientIDPrefixOrigin},
			[]string{"RequireSignedRequestByReference", "AllowedClientIDPrefixes"},
		},
		"x5c-signed by reference without an x509 prefix": {
			Options{RequireSignedRequestByReference: true, RequestObjectX5C: X5CRules{Require: true}, AllowedClientIDPrefixes: ClientIDPrefixRedirectURI | ClientIDPrefixDecentralizedIdentifier},
			[]string{"RequireSignedRequestByReference", "RequestObjectX5C.Require", "AllowedClientIDPrefixes"},
		},
	}
	for name, tt := range tests {
		_, err := Final().With(tt.options)
		var conflict *ConflictError
		if !errors.As(err, &conflict) || !slices.Equal(conflict.Options, tt.names) {
			t.Errorf("%s: error = %v, want a ConflictError naming %v", name, err, tt.names)
		}
	}
	// Each option alone, and the x509 prefixes with both, are satisfiable.
	for _, o := range []Options{
		{RequireSignedRequestByReference: true},
		{AllowedClientIDPrefixes: ClientIDPrefixRedirectURI},
		{RequireSignedRequestByReference: true, RequestObjectX5C: X5CRules{Require: true}, AllowedClientIDPrefixes: ClientIDPrefixX509SanDNS},
	} {
		if _, err := Final().With(o); err != nil {
			t.Errorf("With(%s): %v", o, err)
		}
	}
}

func TestOptionTableCoversEveryField(t *testing.T) {
	var fields []string
	leafFields(t, func(path string, _ reflect.Value) { fields = append(fields, path) })
	var names []string
	for _, opt := range options {
		names = append(names, opt.name)
		var o Options
		if opt.flag != nil {
			*opt.flag(&o) = true
		} else {
			opt.put(&o, 1)
		}
		field := reflect.ValueOf(o).FieldByIndex(fieldIndex(t, opt.name))
		if field.IsZero() || (Options{}).Covers(o) {
			t.Errorf("option %s does not write the field of its name", opt.name)
		}
	}
	if !slices.Equal(names, fields) {
		t.Fatalf("option names %v, want the Options fields %v in order", names, fields)
	}
}

func TestTextFormRoundTrips(t *testing.T) {
	partial, err := Final().With(Options{RequireDPoP: true, RequirePAR: true, IssuerX5C: X5CRules{Require: true}})
	if err != nil {
		t.Fatal(err)
	}
	narrowed, err := HAIP().With(Options{AllowedCredentialFormats: FormatMsoMdoc})
	if err != nil {
		t.Fatal(err)
	}
	restricted, err := Final().With(Options{AllowedCredentialFormats: FormatSDJWTVC | FormatMsoMdoc, AllowedClientIDPrefixes: ClientIDPrefixX509Hash | ClientIDPrefixX509SanDNS})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		profile Profile
		text    string
	}{
		{Final(), "final"},
		{HAIP(), "haip"},
		{Draft13(), "draft13"},
		{Draft24(), "draft24"},
		{partial, "final;IssuerX5C.Require;RequirePAR;RequireDPoP"},
		{narrowed, "haip;AllowedCredentialFormats=mso_mdoc"},
		{restricted, "final;AllowedCredentialFormats=dc+sd-jwt,mso_mdoc;AllowedClientIDPrefixes=x509_san_dns,x509_hash"},
	}
	for _, tt := range tests {
		if got := tt.profile.String(); got != tt.text {
			t.Errorf("String() = %q, want %q", got, tt.text)
		}
		parsed, err := ParseProfile(tt.text)
		if err != nil || parsed != tt.profile {
			t.Errorf("ParseProfile(%q) = %s, %v", tt.text, parsed, err)
		}
		encoded, err := json.Marshal(struct{ P Profile }{tt.profile})
		if err != nil {
			t.Fatal(err)
		}
		var decoded struct{ P Profile }
		if err := json.Unmarshal(encoded, &decoded); err != nil || decoded.P != tt.profile {
			t.Errorf("JSON %s decoded to %s, %v", encoded, decoded.P, err)
		}
	}
	// Every option, alone, round-trips.
	for _, opt := range options {
		var o Options
		if opt.flag != nil {
			*opt.flag(&o) = true
		} else {
			opt.put(&o, 1)
		}
		p, err := Final().With(o)
		if err != nil {
			t.Fatal(err)
		}
		if parsed, err := ParseProfile(p.String()); err != nil || parsed != p {
			t.Errorf("%s: ParseProfile(%q) = %s, %v", opt.name, p.String(), parsed, err)
		}
	}
}

func TestParseProfileRefusesUnknownText(t *testing.T) {
	for _, text := range []string{"", "HAIP", "final;", "final;RequireNothing", "final;RequireDPoP=on", "final;AllowedCredentialFormats", "final;AllowedCredentialFormats=vc+sd-jwt"} {
		if _, err := ParseProfile(text); !errors.Is(err, ErrUnknownProfile) {
			t.Errorf("ParseProfile(%q): error = %v, want ErrUnknownProfile", text, err)
		}
	}
	if _, err := ParseProfile("draft13;RequireDPoP"); !errors.Is(err, ErrDraftProfile) {
		t.Errorf("draft with options: error = %v", err)
	}
	if _, err := ParseProfile("haip;AllowedCredentialFormats=jwt_vc_json"); !errors.Is(err, ErrOptionsConflict) {
		t.Errorf("conflicting text: error = %v", err)
	}
	var p Profile
	if err := json.Unmarshal([]byte(`"bogus"`), &p); !errors.Is(err, ErrUnknownProfile) {
		t.Errorf("json: error = %v", err)
	}
}

func TestOptionsStringNamesTheOptionsInForce(t *testing.T) {
	if got := (Options{}).String(); got != "none" {
		t.Errorf("zero Options = %q", got)
	}
	if got := (Options{RequireDPoP: true, ResponseEncryption: ResponseEncryptionRules{GCMOnly: true}}).String(); got != "RequireDPoP;ResponseEncryption.GCMOnly" {
		t.Errorf("String() = %q", got)
	}
	var refused *OptionError
	if err := Refused("RequireDPoP"); !errors.As(err, &refused) || refused.Option != "RequireDPoP" || err.Error() != "profile option RequireDPoP" {
		t.Errorf("Refused = %v", err)
	}
	if _, coded := common.CodeOf(Refused("RequireDPoP")); coded {
		t.Error("an OptionError must not classify the error it sits beside")
	}
}

func TestOptionsCovers(t *testing.T) {
	partial := HAIPOptions()
	partial.RequirePAR = false
	narrowed := HAIPOptions()
	narrowed.AllowedCredentialFormats = FormatMsoMdoc
	for name, test := range map[string]struct {
		options Options
		want    bool
	}{
		"HAIP":                {HAIP().Options(), true},
		"HAIP narrowed":       {narrowed, true},
		"Final":               {Final().Options(), false},
		"all of HAIP but PAR": {partial, false},
	} {
		if got := test.options.Covers(HAIPOptions()); got != test.want {
			t.Errorf("%s: Covers(HAIPOptions()) = %v, want %v", name, got, test.want)
		}
	}
	if !Final().Options().Covers(Options{}) {
		t.Error("every Options covers the zero Options")
	}
}

func TestHAIPOptionsAreSatisfiable(t *testing.T) {
	if err := HAIPOptions().validate(); err != nil {
		t.Fatal(err)
	}
}
