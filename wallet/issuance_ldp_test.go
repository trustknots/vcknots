package wallet

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/acceptance"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/credential/dataintegrity"
	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// ldpTestIssuer signs eddsa-rdfc-2022 credentials with the issuer key and
// context of the credential/dataintegrity test vectors.
type ldpTestIssuer struct {
	key        ed25519.PrivateKey
	method     string
	contexts   dataintegrity.PinnedContexts
	contextURL string
}

func newLdpTestIssuer(t *testing.T) ldpTestIssuer {
	t.Helper()
	raw, err := os.ReadFile("credential/dataintegrity/testdata/vectors.json")
	require.NoError(t, err)
	var vectors struct {
		Issuer struct {
			PrivateJWK struct{ D string } `json:"privateJwk"`
			VM         string             `json:"vm"`
		} `json:"issuer"`
		Contexts   map[string]any `json:"contexts"`
		ContextURL string         `json:"contextUrl"`
	}
	require.NoError(t, json.Unmarshal(raw, &vectors))
	return ldpTestIssuer{key: seedKey(t, vectors.Issuer.PrivateJWK.D), method: vectors.Issuer.VM, contexts: vectors.Contexts, contextURL: vectors.ContextURL}
}

func (i ldpTestIssuer) did() string {
	did, _, _ := strings.Cut(i.method, "#")
	return did
}

// policy authenticates the issuer's did:key through a DID Configuration the
// Credential Issuer's origin serves, with the issuer's context pinned.
func (i ldpTestIssuer) policy() *acceptance.Policy {
	policy := acceptDIDIssuerPolicy(i.did(), i.method, jose.EdDSA, i.key)
	policy.DataIntegrityContexts = i.contexts
	return policy
}

// credential returns a signed credential whose subject is subjectID.
func (i ldpTestIssuer) credential(t *testing.T, subjectID string) map[string]any {
	t.Helper()
	signed, err := dataintegrity.SignEddsaRdfc2022(map[string]any{
		"@context":          i.contextURL,
		"type":              []any{"VerifiableCredential", "UniversityDegreeCredential"},
		"issuer":            i.did(),
		"validFrom":         "2026-01-01T00:00:00Z",
		"credentialSubject": map[string]any{"id": subjectID, "degreeName": "Computer Science"},
	}, dataintegrity.ProofOptions{
		VerificationMethod: i.method,
		ProofPurpose:       dataintegrity.ProofPurposeAssertionMethod,
		Created:            time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}, i.contexts, func(data []byte) ([]byte, error) { return ed25519.Sign(i.key, data), nil })
	require.NoError(t, err)
	return signed
}

// newLdpDraft13Fixture is a Draft 13 fixture whose configuration is ldp_vc
// and whose issuer answers with credential.
func newLdpDraft13Fixture(t *testing.T, issuer ldpTestIssuer, issued func(holder jose.JSONWebKey) map[string]any, configure ...func(*Config)) *draft13Fixture {
	t.Helper()
	fixture := newDraft13Fixture(t, configure...)
	credential := issued(fixture.key.PublicKey())
	fixture.set(func(f *draft13Fixture) {
		f.configuration = map[string]any{
			"format": "ldp_vc",
			"credential_definition": map[string]any{
				"@context": []any{issuer.contextURL},
				"type":     []any{"VerifiableCredential", "UniversityDegreeCredential"},
			},
			"cryptographic_binding_methods_supported": []string{"did:key"},
			"proof_types_supported": map[string]any{
				"jwt": map[string]any{"proof_signing_alg_values_supported": []string{"ES256"}},
			},
		}
		f.credentialResponse = func(int, map[string]any) (int, any) {
			return http.StatusOK, map[string]any{"credential": credential, "notification_id": "notification-1"}
		}
	})
	return fixture
}

// Draft 13 Appendix A.1.2: an ldp_vc is requested by format with the
// configuration's @context and type, and arrives as a JSON object. It is
// verified with the Data Integrity proof and stored.
func TestDraft13IssuesAnLdpVC(t *testing.T) {
	issuer := newLdpTestIssuer(t)
	fixture := newLdpDraft13Fixture(t, issuer, func(holder jose.JSONWebKey) map[string]any {
		return issuer.credential(t, didKeyOf(t, holder))
	}, func(c *Config) { c.CredentialAcceptance = issuer.policy() })

	result, err := fixture.receivePreAuthorized(t)
	require.NoError(t, err)
	require.Len(t, result.Credentials, 1)
	saved := result.Credentials[0]
	require.Equal(t, string(credential.LdpVc), saved.Entry.MimeType)
	require.Equal(t, issuer.did(), saved.Credential.Issuer)
	require.Equal(t, issuer.method, saved.Verification.IssuerKeyID)
	require.NotNil(t, saved.Verification.IssuerKey)
	require.Equal(t, 1, draft13StoredCount(t, fixture.wallet))

	request := fixture.credentials()[0]
	require.Equal(t, "ldp_vc", request["format"])
	require.Equal(t, map[string]any{
		"@context": []any{issuer.contextURL},
		"type":     []any{"VerifiableCredential", "UniversityDegreeCredential"},
	}, request["credential_definition"])
}

// A policy that cannot verify the proof, a tampered credential and a
// credential bound to another holder are refused and not stored.
func TestDraft13RefusesAnLdpVCItCannotAccept(t *testing.T) {
	issuer := newLdpTestIssuer(t)
	for name, test := range map[string]struct {
		issued func(holder jose.JSONWebKey) map[string]any
		policy *acceptance.Policy
		want   error
	}{
		"a DID the Credential Issuer's origin does not link": {
			issued: func(holder jose.JSONWebKey) map[string]any { return issuer.credential(t, didKeyOf(t, holder)) },
			policy: func() *acceptance.Policy {
				other := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
				otherDID := didKeyOf(t, jose.JSONWebKey{Key: other.Public()})
				policy := acceptDIDIssuerPolicy(otherDID, otherDID, jose.EdDSA, other)
				policy.DataIntegrityContexts = issuer.contexts
				return policy
			}(),
			want: acceptance.ErrIssuerKeyUnresolved,
		},
		"a tampered claim": {
			issued: func(holder jose.JSONWebKey) map[string]any {
				document := issuer.credential(t, didKeyOf(t, holder))
				document["credentialSubject"].(map[string]any)["degreeName"] = "Law"
				return document
			},
			policy: issuer.policy(),
			want:   acceptance.ErrIssuerSignatureInvalid,
		},
		"bound to another holder": {
			issued: func(jose.JSONWebKey) map[string]any {
				return issuer.credential(t, didKeyOf(t, newPrivateJWKForFinalVCITest(t, "other")))
			},
			policy: issuer.policy(),
			want:   acceptance.ErrHolderBindingMismatch,
		},
		"bound to no holder": {
			issued: func(jose.JSONWebKey) map[string]any { return issuer.credential(t, "did:example:holder") },
			policy: issuer.policy(),
			want:   acceptance.ErrHolderBindingMissing,
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newLdpDraft13Fixture(t, issuer, test.issued, func(c *Config) { c.CredentialAcceptance = test.policy })
			result, err := fixture.receivePreAuthorized(t)
			require.ErrorIs(t, err, test.want)
			require.NotNil(t, result.Notification)
			require.Zero(t, draft13StoredCount(t, fixture.wallet))
		})
	}
}

// OpenID4VCI 1.0 Appendix A.1.2: an ldp_vc in the credentials array is the
// JSON object itself.
func TestIssuanceAcceptsAnLdpVC(t *testing.T) {
	issuer := newLdpTestIssuer(t)
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.credentialFormat = "ldp_vc"
		f.bindingMethods = []string{"did:key"}
	})
	fixture.credentialHandler = func(w http.ResponseWriter, _ *http.Request) {
		mockserver.JSONResponse(w, http.StatusOK, map[string]any{"credentials": []any{
			map[string]any{"credential": issuer.credential(t, didKeyOf(t, fixture.holderKey))},
		}})
	}
	fixture.wallet.credentialAcceptance = issuer.policy()

	result, err := fixture.receive(fixture.issuanceRequest())
	require.NoError(t, err)
	require.Len(t, result.Credentials, 1)
	require.Equal(t, string(credential.LdpVc), result.Credentials[0].Entry.MimeType)
	require.Equal(t, issuer.method, result.Credentials[0].Verification.IssuerKeyID)
}

// HAIP Section 4.1 allows dc+sd-jwt and mso_mdoc only.
func TestIssuanceRefusesAnLdpVCUnderHAIP(t *testing.T) {
	fixture := newHAIPIssuanceFixture(t, func(f *finalIssuanceFixture) { f.credentialFormat = "ldp_vc" })
	_, err := fixture.wallet.BeginIssuance(context.Background(), fixture.issuanceRequest())
	require.ErrorIs(t, err, receiverTypes.ErrInvalidMetadata)
	require.ErrorContains(t, err, "profile option AllowedCredentialFormats requires credential format dc+sd-jwt or mso_mdoc")
	require.Zero(t, fixture.parCalls)
}
