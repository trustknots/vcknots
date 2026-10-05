package wallet

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// draft13BindingConfiguration is the fixture's SD-JWT VC configuration with
// the binding methods given.
func draft13BindingConfiguration(format string, methods ...string) map[string]any {
	configuration := map[string]any{
		"format": format,
		"vct":    "https://credentials.example/degree",
		"proof_types_supported": map[string]any{
			"jwt": map[string]any{"proof_signing_alg_values_supported": []string{"ES256"}},
		},
	}
	if format == "jwt_vc_json" {
		delete(configuration, "vct")
		configuration["credential_definition"] = map[string]any{"type": []string{"VerifiableCredential", "UniversityDegree"}}
	}
	if methods != nil {
		configuration["cryptographic_binding_methods_supported"] = methods
	}
	return configuration
}

// Draft 13 Section 7.2.1.1: the key proof names the key by kid (a DID URL) or
// by jwk, and cryptographic_binding_methods_supported (Section 11.2.3) says
// which the issuer binds to. The wallet takes the first listed method it can
// produce, jwk or did:key, whatever the format.
func TestDraft13KeyProofFollowsTheAdvertisedBindingMethods(t *testing.T) {
	for name, test := range map[string]struct {
		format  string
		methods []string
		wantJWK bool
	}{
		"SD-JWT VC, did:web then jwk":  {"vc+sd-jwt", []string{"did:web", "jwk"}, true},
		"SD-JWT VC, did:key then jwk":  {"vc+sd-jwt", []string{"did:key", "jwk"}, false},
		"SD-JWT VC, jwk then did:key":  {"vc+sd-jwt", []string{"jwk", "did:key"}, true},
		"jwt_vc_json, jwk":             {"jwt_vc_json", []string{"jwk"}, true},
		"jwt_vc_json, did:key":         {"jwt_vc_json", []string{"did:key"}, false},
		"SD-JWT VC, no binding listed": {"vc+sd-jwt", nil, false},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newDraft13Fixture(t)
			fixture.set(func(f *draft13Fixture) { f.configuration = draft13BindingConfiguration(test.format, test.methods...) })
			if test.format == "jwt_vc_json" {
				jwtVC := draft13JWTVC(t, fixture.issuerKey, fixture.key.PublicKey())
				fixture.set(func(f *draft13Fixture) {
					f.credentialResponse = func(int, map[string]any) (int, any) {
						return http.StatusOK, map[string]any{"credential": jwtVC}
					}
				})
			}
			_, err := fixture.receivePreAuthorized(t)
			require.NoError(t, err)
			_, header, _ := draft13ProofParts(t, fixture.credentials()[0])
			if test.wantJWK {
				require.Contains(t, header, "jwk")
				require.NotContains(t, header, "kid", "kid MUST NOT be present if jwk is present")
				return
			}
			require.NotContains(t, header, "jwk")
			kid, _ := header["kid"].(string)
			require.True(t, strings.HasPrefix(kid, "did:key:"), "kid %q", kid)
		})
	}
}

// A configuration that binds only to methods the wallet cannot produce is
// refused before the Credential Request: a did:key proof would bind the
// credential to a key the issuer does not accept.
func TestDraft13RefusesAConfigurationWithoutAUsableBindingMethod(t *testing.T) {
	fixture := newDraft13Fixture(t)
	fixture.set(func(f *draft13Fixture) {
		f.configuration = draft13BindingConfiguration("vc+sd-jwt", "did:web", "cose_key")
	})
	grant := fixture.preAuthorize(t, fixture.wallet)
	_, err := fixture.wallet.Draft13().RequestCredential(context.Background(), grant, fixture.holder())
	require.ErrorIs(t, err, ErrCryptographicBindingMethodUnsupported)
	require.Empty(t, fixture.credentials())
}

// Section 7.2: the proof is REQUIRED only when proof_types_supported is
// present and non-empty, so an unbound configuration is requested without a
// holder key.
func TestDraft13RequestsAnUnboundCredentialWithoutAProof(t *testing.T) {
	fixture := newDraft13Fixture(t)
	fixture.set(func(f *draft13Fixture) {
		f.configuration = map[string]any{"format": "vc+sd-jwt", "vct": "https://credentials.example/degree"}
	})
	grant := fixture.preAuthorize(t, fixture.wallet)
	result, err := fixture.wallet.Draft13().RequestCredential(context.Background(), grant, CredentialRequest{})
	require.NoError(t, err)
	require.Len(t, result.Credentials, 1)
	require.NotContains(t, fixture.credentials()[0], "proof")
}
