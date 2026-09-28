package acceptance

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/credential/dataintegrity"
	"github.com/trustknots/vcknots/wallet/idprof/issuerkeys"
	"github.com/trustknots/vcknots/wallet/profile"
)

// ldpIssuer signs eddsa-rdfc-2022 credentials with the issuer key and context
// of the credential/dataintegrity test vectors.
type ldpIssuer struct {
	key        ed25519.PrivateKey
	method     string
	contexts   dataintegrity.PinnedContexts
	contextURL string
}

func newLdpIssuer(t *testing.T) ldpIssuer {
	t.Helper()
	raw, err := os.ReadFile("../credential/dataintegrity/testdata/vectors.json")
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
	seed, err := base64.RawURLEncoding.DecodeString(vectors.Issuer.PrivateJWK.D)
	require.NoError(t, err)
	return ldpIssuer{key: ed25519.NewKeyFromSeed(seed), method: vectors.Issuer.VM, contexts: vectors.Contexts, contextURL: vectors.ContextURL}
}

func (i ldpIssuer) did() string {
	did, _, _ := strings.Cut(i.method, "#")
	return did
}

// sign returns the signed credential issued by issuer, valid until validUntil.
func (i ldpIssuer) sign(t *testing.T, issuer string, validUntil time.Time) []byte {
	t.Helper()
	document := map[string]any{
		"@context":          i.contextURL,
		"type":              []any{"VerifiableCredential", "UniversityDegreeCredential"},
		"issuer":            issuer,
		"validFrom":         "2026-01-01T00:00:00Z",
		"validUntil":        validUntil.UTC().Format(time.RFC3339),
		"credentialSubject": map[string]any{"id": "did:example:holder", "degreeName": "Computer Science"},
	}
	signed, err := dataintegrity.SignEddsaRdfc2022(document, dataintegrity.ProofOptions{
		VerificationMethod: i.method,
		ProofPurpose:       dataintegrity.ProofPurposeAssertionMethod,
		Created:            time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}, i.contexts, func(data []byte) ([]byte, error) { return ed25519.Sign(i.key, data), nil })
	require.NoError(t, err)
	raw, err := json.Marshal(signed)
	require.NoError(t, err)
	return raw
}

func ldpOptions() Options {
	return Options{Flavor: credential.LdpVc, CredentialIssuer: testCredentialIssuer}
}

// policy authenticates the issuer's did:key through a DID Configuration the
// Credential Issuer's origin publishes (OpenID4VCI 1.0 §14.4), with the
// issuer's contexts pinned.
func (i ldpIssuer) policy(t *testing.T) Policy {
	t.Helper()
	network := newKeyNetwork()
	network.linkDID(t, testCredentialIssuer, i.did(), i.method, jose.EdDSA, i.key)
	return Policy{
		IssuerKeys:            network.resolver(issuerkeys.Mechanisms{DIDKey: true, DIDConfiguration: true}),
		DataIntegrityContexts: i.contexts,
	}
}

func TestVerifyDataIntegrityCredential(t *testing.T) {
	issuer := newLdpIssuer(t)
	raw := issuer.sign(t, issuer.did(), time.Now().Add(time.Hour))
	acceptor := newTestAcceptor(t, profile.Final())

	t.Run("a DID key bound by a DID Configuration verifies the proof", func(t *testing.T) {
		parsed, verification, err := acceptor.Verify(t.Context(), raw, issuer.policy(t), ldpOptions())
		require.NoError(t, err)
		require.Equal(t, issuer.did(), parsed.Issuer)
		require.Equal(t, issuer.method, verification.IssuerKeyID)
		require.NotNil(t, verification.IssuerKey)
		require.Equal(t, issuerkeys.MechanismDIDConfigurationBinding, verification.Mechanism)
		require.Equal(t, issuer.did(), verification.DID)
		require.Equal(t, issuer.did(), verification.Issuer)
	})

	t.Run("a DID without a DID Configuration binding is refused", func(t *testing.T) {
		policy := Policy{
			IssuerKeys:            newKeyNetwork().resolver(issuerkeys.Mechanisms{DIDKey: true, DIDConfiguration: true}),
			DataIntegrityContexts: issuer.contexts,
		}
		_, _, err := acceptor.Verify(t.Context(), raw, policy, ldpOptions())
		require.ErrorIs(t, err, ErrIssuerKeyUnresolved)
		require.ErrorIs(t, err, issuerkeys.ErrDIDOnlyTrustUnsupported)
	})

	t.Run("a DID Configuration of another origin does not bind", func(t *testing.T) {
		options := ldpOptions()
		options.CredentialIssuer = "https://other.example.test"
		_, _, err := acceptor.Verify(t.Context(), raw, issuer.policy(t), options)
		require.ErrorIs(t, err, issuerkeys.ErrDIDOnlyTrustUnsupported)
	})

	t.Run("unpinned contexts fail closed", func(t *testing.T) {
		policy := issuer.policy(t)
		policy.DataIntegrityContexts = nil
		_, _, err := acceptor.Verify(t.Context(), raw, policy, ldpOptions())
		require.ErrorIs(t, err, ErrIssuerSignatureInvalid)
		require.ErrorIs(t, err, dataintegrity.ErrContextNotPinned)
	})

	t.Run("a tampered claim fails", func(t *testing.T) {
		tampered := []byte(strings.Replace(string(raw), "Computer Science", "Law", 1))
		_, _, err := acceptor.Verify(t.Context(), tampered, issuer.policy(t), ldpOptions())
		require.ErrorIs(t, err, ErrIssuerSignatureInvalid)
	})

	t.Run("IssuerX509 alone authenticates nothing", func(t *testing.T) {
		chain := newTestIssuerChain(t, []string{"issuer.example"})
		_, _, err := acceptor.Verify(t.Context(), raw, x509Trust(chain.anchors()), ldpOptions())
		require.ErrorIs(t, err, ErrIssuerKeyUnresolved)
	})

	t.Run("no policy mechanism fails closed", func(t *testing.T) {
		_, _, err := acceptor.Verify(t.Context(), raw, Policy{}, ldpOptions())
		require.ErrorIs(t, err, ErrIssuerKeyUnresolved)
	})
}

// A verificationMethod outside the issuer's identifier cannot sign for it,
// whatever key the resolver returns.
func TestVerifyDataIntegrityCredentialRequiresTheIssuersVerificationMethod(t *testing.T) {
	issuer := newLdpIssuer(t)
	raw := issuer.sign(t, "https://issuer.example", time.Now().Add(time.Hour))
	_, _, err := newTestAcceptor(t, profile.Final()).Verify(t.Context(), raw, issuer.policy(t), ldpOptions())
	require.ErrorIs(t, err, ErrIssuerSignatureInvalid)
	require.ErrorContains(t, err, "is not controlled by issuer")
}

func TestVerifyDataIntegrityCredentialChecksValidity(t *testing.T) {
	issuer := newLdpIssuer(t)
	raw := issuer.sign(t, issuer.did(), time.Now().Add(-time.Hour))
	_, _, err := newTestAcceptor(t, profile.Final()).Verify(t.Context(), raw, issuer.policy(t), ldpOptions())
	require.ErrorIs(t, err, ErrCredentialExpired)
}

func TestParseDataIntegrityCredential(t *testing.T) {
	_, _, err := newTestAcceptor(t, profile.Final()).Parse([]byte(`"not an object"`), ldpOptions())
	require.ErrorIs(t, err, ErrCredentialParse)

	issuer := newLdpIssuer(t)
	parsed, _, err := newTestAcceptor(t, profile.Final()).Parse(issuer.sign(t, issuer.did(), time.Now().Add(-time.Hour)), ldpOptions())
	require.NoError(t, err)
	require.Equal(t, issuer.did(), parsed.Issuer)
}
