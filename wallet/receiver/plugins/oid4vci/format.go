package oid4vci

import (
	"fmt"

	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/profile"
)

// ErrCredentialFormatUnsupported reports a Credential Format Identifier the
// wallet cannot receive under the profile's OpenID4VCI version: an identifier
// the version does not define (including one another version defines, such
// as Draft 13's vc+sd-jwt under OpenID4VCI 1.0), or one it defines that the
// library has no serializer for (mso_mdoc, jwt_vc_json-ld).
var ErrCredentialFormatUnsupported = common.NewCodedError("credential_format_unsupported", "credential format is not supported under the profile")

// finalCredentialFormats are the Credential Format Identifiers of OpenID4VCI
// 1.0 Appendix A the library receives.
var finalCredentialFormats = map[string]credential.SupportedSerializationFlavor{
	"jwt_vc_json": credential.JwtVc,   // Appendix A.1.1
	"ldp_vc":      credential.LdpVc,   // Appendix A.1.2
	"dc+sd-jwt":   credential.SDJwtVC, // Appendix A.3
}

// draft13CredentialFormats are the Credential Format Identifiers of
// OpenID4VCI Draft 13 Appendix A the library receives.
var draft13CredentialFormats = map[string]credential.SupportedSerializationFlavor{
	"jwt_vc_json": credential.JwtVc,   // Appendix A.1.1
	"ldp_vc":      credential.LdpVc,   // Appendix A.1.2
	"vc+sd-jwt":   credential.SDJwtVC, // Appendix A.3
}

// CredentialFormatFlavor maps a Credential Format Identifier to the
// serialization flavor the wallet parses it with, by the table of the
// OpenID4VCI version p runs: Draft 13 Appendix A for profile.Draft13, and
// OpenID4VCI 1.0 Appendix A for the 1.0 profiles (Final, HAIP). Identifiers
// are compared exactly. Any identifier outside the table is
// ErrCredentialFormatUnsupported; nothing is guessed from an unknown one.
func CredentialFormatFlavor(p profile.Profile, format string) (credential.SupportedSerializationFlavor, error) {
	table := finalCredentialFormats
	switch {
	case p == profile.Draft13():
		table = draft13CredentialFormats
	case p.Draft():
		return "", fmt.Errorf("%w: %s is not an OpenID4VCI profile", ErrCredentialFormatUnsupported, p)
	}
	if flavor, ok := table[format]; ok {
		return flavor, nil
	}
	return "", fmt.Errorf("%w: %q under %s", ErrCredentialFormatUnsupported, format, p)
}
