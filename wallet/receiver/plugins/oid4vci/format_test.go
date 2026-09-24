package oid4vci

import (
	"testing"

	"github.com/trustknots/vcknots/wallet/credential"
)

func TestOID4VCICredentialFormatToSerializationFlavor(t *testing.T) {
	for format, want := range map[string]credential.SupportedSerializationFlavor{
		"jwt_vc_json": credential.JwtVc,
		"dc+sd-jwt":   credential.SDJwtVC,
		// Draft 13 Appendix A.3 names SD-JWT VC "vc+sd-jwt".
		"vc+sd-jwt": credential.SDJwtVC,
		"ldp_vc":    credential.LdpVc,
	} {
		got, err := OID4VCICredentialFormatToSerializationFlavor(format)
		if err != nil || got != want {
			t.Errorf("%s: got %q, %v; want %q", format, got, err, want)
		}
	}
	if _, err := OID4VCICredentialFormatToSerializationFlavor("mso_mdoc"); err == nil {
		t.Error("an unsupported format must be an error")
	}
}
