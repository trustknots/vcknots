package oid4vci

import (
	"errors"
	"testing"

	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/profile"
)

// Each OpenID4VCI version has its own Appendix A table, compared exactly; an
// identifier of the other version, a legacy alias or an unknown value is
// refused rather than guessed.
func TestCredentialFormatFlavor(t *testing.T) {
	accepted := map[profile.Profile]map[string]credential.SupportedSerializationFlavor{
		profile.Final():   {"jwt_vc_json": credential.JwtVc, "ldp_vc": credential.LdpVc, "dc+sd-jwt": credential.SDJwtVC},
		profile.HAIP():    {"jwt_vc_json": credential.JwtVc, "ldp_vc": credential.LdpVc, "dc+sd-jwt": credential.SDJwtVC},
		profile.Draft13(): {"jwt_vc_json": credential.JwtVc, "ldp_vc": credential.LdpVc, "vc+sd-jwt": credential.SDJwtVC},
	}
	refused := map[profile.Profile][]string{
		profile.Final():   {"vc+sd-jwt", "jwt_vc", "application/vc+jwt", "application/dc+sd-jwt", "vc+jwt", "mso_mdoc", "jwt_vc_json-ld", "JWT_VC_JSON", " dc+sd-jwt", "unknown", ""},
		profile.HAIP():    {"vc+sd-jwt", "jwt_vc", "unknown"},
		profile.Draft13(): {"dc+sd-jwt", "jwt_vc", "application/vc+jwt", "mso_mdoc", "jwt_vc_json-ld", "unknown"},
		profile.Draft24(): {"jwt_vc_json"},
	}
	for p, table := range accepted {
		for format, want := range table {
			got, err := CredentialFormatFlavor(p, format)
			if err != nil || got != want {
				t.Errorf("%s %q: got %q, %v; want %q", p, format, got, err, want)
			}
		}
	}
	for p, formats := range refused {
		for _, format := range formats {
			if got, err := CredentialFormatFlavor(p, format); !errors.Is(err, ErrCredentialFormatUnsupported) {
				t.Errorf("%s %q: got %q, %v; want ErrCredentialFormatUnsupported", p, format, got, err)
			}
		}
	}
}
