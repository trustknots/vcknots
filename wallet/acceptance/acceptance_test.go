package acceptance

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/internal/testutil"
	"github.com/trustknots/vcknots/wallet/profile"
	"github.com/trustknots/vcknots/wallet/serializer"
	"github.com/trustknots/vcknots/wallet/verifier"
)

// TestParseChecksOnlyWhatNeedsNoPolicy pins Parse: the credential must parse
// and a cnf must match the holder key, and nothing about the issuer is
// checked.
func TestParseChecksOnlyWhatNeedsNoPolicy(t *testing.T) {
	acceptor := newTestAcceptor(t, profile.Final)
	holder := newHolderKey(t)

	t.Run("a malformed credential is refused", func(t *testing.T) {
		_, _, err := acceptor.Parse([]byte("this-is-not-a-credential"), sdJWT(&holder))
		require.ErrorIs(t, err, ErrCredentialParse)
	})

	t.Run("a cnf bound to another holder key is refused", func(t *testing.T) {
		other := newHolderKey(t)
		wire := buildWire(t, testWire{cnf: &other, signingKey: testutil.NewP256Key(t)})
		_, _, err := acceptor.Parse([]byte(wire), sdJWT(&holder))
		require.ErrorIs(t, err, ErrHolderBindingMismatch)
	})

	t.Run("a matching cnf is reported bound without an issuer", func(t *testing.T) {
		wire := buildWire(t, testWire{cnf: &holder, signingKey: testutil.NewP256Key(t), tamperSignature: true})
		parsed, verification, err := acceptor.Parse([]byte(wire), sdJWT(&holder))
		require.NoError(t, err)
		require.NotNil(t, parsed)
		require.True(t, verification.HolderBound)
		require.Nil(t, verification.IssuerKey)
	})
}

func TestVerifyX509Policy(t *testing.T) {
	acceptor := newTestAcceptor(t, profile.Final)
	holder := newHolderKey(t)
	chain := newTestIssuerChain(t, []string{"issuer.example.test"})
	otherChain := newTestIssuerChain(t, []string{"issuer.example.test"})
	signed := func(spec testWire) []byte {
		spec.signingKey = chain.leafKey
		spec.x5c = chain.x5c()
		spec.cnf = &holder
		return []byte(buildWire(t, spec))
	}

	t.Run("a valid x5c credential records the chain", func(t *testing.T) {
		_, verification, err := acceptor.Verify(t.Context(), signed(testWire{disclosures: map[string]string{"given_name": "Taro"}}), x509Trust(chain.anchors(), false), sdJWT(&holder))
		require.NoError(t, err)
		require.Len(t, verification.CertificateSHA256, 2)
		require.GreaterOrEqual(t, verification.RevocationUnadvertised, 1)
		require.Equal(t, verification.CertificateSHA256[0], verification.IssuerKeyID)
	})

	rejections := map[string]struct {
		wire    []byte
		policy  Policy
		message string
	}{
		"anchors that do not contain the CA": {signed(testWire{}), x509Trust(otherChain.anchors(), false), "issuer certificate chain is not trusted"},
		"an expired credential":              {signed(testWire{exp: time.Now().Add(-time.Hour)}), x509Trust(chain.anchors(), false), "expired"},
		"a tampered signature":               {signed(testWire{tamperSignature: true}), x509Trust(chain.anchors(), false), "issuer signature could not be verified"},
		"a disclosure without a digest":      {signed(testWire{disclosures: map[string]string{"given_name": "Taro"}, extraDisclosure: true}), x509Trust(chain.anchors(), false), "disclosure is not referenced"},
		"an issuer DNS binding mismatch":     {signed(testWire{issuer: "https://other.example.test"}), x509Trust(chain.anchors(), true), "not bound to issuer host"},
		"a non SD-JWT typ":                   {signed(testWire{typ: "JWT"}), x509Trust(chain.anchors(), false), "typ header"},
		"x5c without configured X.509 trust": {signed(testWire{}), Policy{}, "x5c issuer authentication is not configured"},
	}
	for name, testCase := range rejections {
		t.Run(name+" is refused", func(t *testing.T) {
			_, _, err := acceptor.Verify(t.Context(), testCase.wire, testCase.policy, sdJWT(&holder))
			require.ErrorContains(t, err, testCase.message)
		})
	}

	t.Run("an issuer DNS binding match is accepted", func(t *testing.T) {
		_, _, err := acceptor.Verify(t.Context(), signed(testWire{issuer: "https://issuer.example.test"}), x509Trust(chain.anchors(), true), sdJWT(&holder))
		require.NoError(t, err)
	})

	t.Run("x5c is ignored when the caller resolves keys without X.509 trust", func(t *testing.T) {
		_, verification, err := acceptor.Verify(t.Context(), signed(testWire{}), resolving(jose.JSONWebKey{Key: chain.leafKey.Public(), KeyID: "leaf"}), sdJWT(&holder))
		require.NoError(t, err)
		require.Nil(t, verification.CertificateSHA256)
		require.Equal(t, "leaf", verification.IssuerKeyID)
	})
}

func TestVerifyResolvedIssuerKeys(t *testing.T) {
	acceptor := newTestAcceptor(t, profile.Final)
	issuerKey := testutil.NewP256Key(t)
	holder := newHolderKey(t)
	wire := []byte(buildWire(t, testWire{signingKey: issuerKey, kid: "issuer-key-1", cnf: &holder}))

	t.Run("the resolved key verifies and records the kid", func(t *testing.T) {
		_, verification, err := acceptor.Verify(t.Context(), wire, resolving(jose.JSONWebKey{Key: &issuerKey.PublicKey, KeyID: "issuer-key-1", Algorithm: "ES256"}), sdJWT(&holder))
		require.NoError(t, err)
		require.Equal(t, "issuer-key-1", verification.IssuerKeyID)
	})

	t.Run("only wrong keys are a signature failure", func(t *testing.T) {
		wrong := testutil.NewP256Key(t)
		_, _, err := acceptor.Verify(t.Context(), wire, resolving(jose.JSONWebKey{Key: &wrong.PublicKey, KeyID: "issuer-key-1", Algorithm: "ES256"}), sdJWT(&holder))
		require.ErrorIs(t, err, ErrIssuerSignatureInvalid)
	})

	t.Run("no resolver and no x5c is unresolved", func(t *testing.T) {
		_, _, err := acceptor.Verify(t.Context(), wire, Policy{}, sdJWT(&holder))
		require.ErrorIs(t, err, ErrIssuerKeyUnresolved)
		require.ErrorContains(t, err, "issuer key resolution is not configured")
	})
}

func TestVerifyUnverifiedIssuer(t *testing.T) {
	acceptor := newTestAcceptor(t, profile.Final)
	holder := newHolderKey(t)
	other := newHolderKey(t)
	chain := newTestIssuerChain(t, []string{"issuer.example.test"})
	wire := []byte(buildWire(t, testWire{signingKey: chain.leafKey, x5c: chain.x5c(), cnf: &holder}))
	permissive := Policy{UnverifiedIssuer: true}

	t.Run("accepts and records no issuer authentication", func(t *testing.T) {
		_, verification, err := acceptor.Verify(t.Context(), wire, permissive, sdJWT(&holder))
		require.NoError(t, err)
		require.True(t, verification.HolderBound)
		require.Nil(t, verification.CertificateSHA256)
		require.Empty(t, verification.IssuerKeyID)
		require.Nil(t, verification.IssuerKey)
	})

	t.Run("still checks the holder binding", func(t *testing.T) {
		_, _, err := acceptor.Verify(t.Context(), wire, permissive, sdJWT(&other))
		require.ErrorIs(t, err, ErrHolderBindingMismatch)
	})

	t.Run("still checks validity", func(t *testing.T) {
		expired := buildWire(t, testWire{signingKey: chain.leafKey, x5c: chain.x5c(), cnf: &holder, exp: time.Now().Add(-time.Hour)})
		_, _, err := acceptor.Verify(t.Context(), []byte(expired), permissive, sdJWT(&holder))
		require.ErrorIs(t, err, ErrCredentialExpired)
	})

	t.Run("yields to configured issuer trust", func(t *testing.T) {
		policy := x509Trust(newTestIssuerChain(t, nil).anchors(), false)
		policy.UnverifiedIssuer = true
		_, _, err := acceptor.Verify(t.Context(), wire, policy, sdJWT(&holder))
		require.ErrorContains(t, err, "issuer certificate chain is not trusted")
	})

	t.Run("an exp beyond any date is malformed", func(t *testing.T) {
		far := buildWire(t, testWire{signingKey: testutil.NewP256Key(t), cnf: &holder, exp: time.Unix(9e15, 0)})
		_, _, err := acceptor.Verify(t.Context(), []byte(far), permissive, sdJWT(&holder))
		require.ErrorIs(t, err, ErrCredentialParse)
	})
}

func TestVerifyHAIPRejectsAnchorInX5CWithRootCAs(t *testing.T) {
	holder := newHolderKey(t)
	chain := newTestIssuerChain(t, []string{"issuer.example.test"})
	wire := []byte(buildWire(t, testWire{signingKey: chain.leafKey, x5c: chain.x5c(), cnf: &holder}))
	roots := x509.NewCertPool()
	roots.AddCert(chain.caCert)
	policy := Policy{IssuerX509: &IssuerX509TrustOptions{RootCAs: roots, AllowUnadvertisedRevocation: true}}

	_, verification, err := newTestAcceptor(t, profile.Final).Verify(t.Context(), wire, policy, sdJWT(&holder))
	require.NoError(t, err)
	require.Len(t, verification.CertificateSHA256, 2)

	_, _, err = newTestAcceptor(t, profile.HAIP).Verify(t.Context(), wire, policy, sdJWT(&holder))
	require.ErrorIs(t, err, ErrHAIPTrustAnchorInX5C)
}

func TestVerifyRejectsUnsupportedConfirmationMethod(t *testing.T) {
	acceptor := newTestAcceptor(t, profile.Final)
	issuerKey := testutil.NewP256Key(t)
	holder := newHolderKey(t)
	policy := resolving(jose.JSONWebKey{Key: &issuerKey.PublicKey, KeyID: "issuer-key-1", Algorithm: "ES256"})

	for member, confirmation := range map[string]map[string]any{
		"kid":      {"kid": "urn:issuer:holder-key-1"},
		"x5t#S256": {"x5t#S256": "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2"},
		"jwe":      {"jwe": "eyJhbGciOiJSU0EtT0FFUCJ9.encrypted.key"},
	} {
		t.Run("cnf."+member+" is refused", func(t *testing.T) {
			wire := buildWire(t, testWire{signingKey: issuerKey, kid: "issuer-key-1", cnfRaw: confirmation})
			_, _, err := acceptor.Verify(t.Context(), []byte(wire), policy, sdJWT(&holder))
			require.ErrorIs(t, err, ErrHolderBindingConfirmationUnsupported)
			require.ErrorContains(t, err, "cnf members: "+member)
		})
	}

	t.Run("cnf.jwk alongside another member is accepted", func(t *testing.T) {
		wire := buildWire(t, testWire{signingKey: issuerKey, kid: "issuer-key-1", cnfRaw: map[string]any{"jwk": holder.Public(), "kid": "urn:issuer:holder-key-1"}})
		_, verification, err := acceptor.Verify(t.Context(), []byte(wire), policy, sdJWT(&holder))
		require.NoError(t, err)
		require.True(t, verification.HolderBound)
	})

	t.Run("no cnf is accepted unbound", func(t *testing.T) {
		wire := buildWire(t, testWire{signingKey: issuerKey, kid: "issuer-key-1"})
		_, verification, err := acceptor.Verify(t.Context(), []byte(wire), policy, sdJWT(&holder))
		require.NoError(t, err)
		require.False(t, verification.HolderBound)
	})
}

type testIssuer struct {
	algorithm jose.SignatureAlgorithm
	private   any
	public    jose.JSONWebKey
}

// testIssuers is one issuer per algorithm the bundled verifier implements.
func testIssuers(t *testing.T) []testIssuer {
	t.Helper()
	issuers := make([]testIssuer, 0, 10)
	for _, ec := range []struct {
		algorithm jose.SignatureAlgorithm
		curve     elliptic.Curve
	}{{jose.ES256, elliptic.P256()}, {jose.ES384, elliptic.P384()}, {jose.ES512, elliptic.P521()}} {
		key, err := ecdsa.GenerateKey(ec.curve, rand.Reader)
		require.NoError(t, err)
		issuers = append(issuers, testIssuer{ec.algorithm, key, jose.JSONWebKey{Key: &key.PublicKey, KeyID: "issuer-key-1", Algorithm: string(ec.algorithm)}})
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	for _, algorithm := range []jose.SignatureAlgorithm{jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512} {
		issuers = append(issuers, testIssuer{algorithm, rsaKey, jose.JSONWebKey{Key: &rsaKey.PublicKey, KeyID: "issuer-key-1", Algorithm: string(algorithm)}})
	}
	edPublic, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	issuers = append(issuers, testIssuer{jose.EdDSA, edPrivate, jose.JSONWebKey{Key: edPublic, KeyID: "issuer-key-1", Algorithm: string(jose.EdDSA)}})
	return issuers
}

// TestVerifySigningAlgorithms proves every registered algorithm verifies a
// real credential, and that only a policy listing it makes it acceptable.
func TestVerifySigningAlgorithms(t *testing.T) {
	acceptor := newTestAcceptor(t, profile.Final)
	holder := newHolderKey(t)
	for _, issuer := range testIssuers(t) {
		t.Run(string(issuer.algorithm), func(t *testing.T) {
			spec := testWire{alg: issuer.algorithm, signer: issuer.private, kid: "issuer-key-1", cnf: &holder}
			wire := []byte(buildWire(t, spec))
			// The key goes through JSON, as a JWKS or DID document delivers it.
			encoded, err := issuer.public.MarshalJSON()
			require.NoError(t, err)
			var decoded jose.JSONWebKey
			require.NoError(t, decoded.UnmarshalJSON(encoded))

			listed := resolving(decoded)
			listed.SigningAlgorithms = []jose.SignatureAlgorithm{issuer.algorithm}
			_, verification, err := acceptor.Verify(t.Context(), wire, listed, sdJWT(&holder))
			require.NoError(t, err)
			require.Equal(t, "issuer-key-1", verification.IssuerKeyID)
			require.True(t, verification.HolderBound)

			spec.tamperSignature = true
			_, _, err = acceptor.Verify(t.Context(), []byte(buildWire(t, spec)), listed, sdJWT(&holder))
			require.ErrorIs(t, err, ErrIssuerSignatureInvalid)

			_, _, err = acceptor.Verify(t.Context(), wire, resolving(decoded), sdJWT(&holder))
			if issuer.algorithm == jose.ES256 {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, ErrCredentialAlgUnsupported)
			require.ErrorContains(t, err, "is not listed by the credential acceptance policy")
		})
	}
}

// TestAlgorithmListsAreCopies pins that callers cannot widen the defaults
// process-wide.
func TestAlgorithmListsAreCopies(t *testing.T) {
	algorithms := DefaultSigningAlgorithms()
	algorithms[0] = jose.RS256
	require.Equal(t, []jose.SignatureAlgorithm{jose.ES256}, DefaultSigningAlgorithms())

	sdAlgorithms := AcceptedSDAlgorithms()
	sdAlgorithms[0] = "md5"
	require.Equal(t, []string{"sha-256", "sha-384", "sha-512"}, AcceptedSDAlgorithms())
}

// TestVerifyAlgorithmWithoutPlugin pins that listing an algorithm no verifier
// implements does not make it acceptable, and "none" never is.
func TestVerifyAlgorithmWithoutPlugin(t *testing.T) {
	acceptor := newTestAcceptor(t, profile.Final)
	holder := newHolderKey(t)
	issuerKey := testutil.NewP256Key(t)
	policy := resolving(jose.JSONWebKey{Key: &issuerKey.PublicKey, KeyID: "issuer-key-1", Algorithm: "ES256"})
	policy.SigningAlgorithms = []jose.SignatureAlgorithm{jose.ES256, jose.HS256, "none"}

	_, _, err := acceptor.Verify(t.Context(), []byte(buildWire(t, testWire{signingKey: issuerKey, kid: "issuer-key-1", cnf: &holder})), policy, sdJWT(&holder))
	require.NoError(t, err)

	_, _, err = acceptor.Verify(t.Context(), []byte(unsignedWire(t, "HS256")), policy, sdJWT(&holder))
	require.ErrorIs(t, err, ErrCredentialAlgUnsupported)
	require.ErrorContains(t, err, "is not supported by the verifier")

	_, _, err = acceptor.Verify(t.Context(), []byte(unsignedWire(t, "none")), policy, sdJWT(&holder))
	require.ErrorIs(t, err, ErrCredentialAlgUnsupported)
	require.ErrorContains(t, err, "alg header is missing or none")
}

// TestVerifyTypedFailures walks every sentinel. Each case first accepts a
// control credential, so the rejection cannot come from a broken fixture.
func TestVerifyTypedFailures(t *testing.T) {
	holder := newHolderKey(t)
	otherHolder := newHolderKey(t)
	issuerKey := testutil.NewP256Key(t)
	issuerJWK := jose.JSONWebKey{Key: &issuerKey.PublicKey, KeyID: "issuer-key-1", Algorithm: "ES256"}
	chain := newTestIssuerChain(t, []string{"issuer.example.test"})

	resolvingPolicy := Policy{ResolveIssuerKeys: func(_ string, header map[string]any) ([]jose.JSONWebKey, error) {
		if kid, _ := header["kid"].(string); kid != "issuer-key-1" {
			return nil, nil
		}
		return []jose.JSONWebKey{issuerJWK}, nil
	}}
	bindingPolicy := resolvingPolicy
	bindingPolicy.RequireHolderBinding = true
	signed := func(spec testWire) string {
		if spec.signingKey == nil && spec.signer == nil {
			spec.signingKey = issuerKey
			spec.kid = "issuer-key-1"
		}
		if spec.cnfRaw == nil && spec.cnf == nil {
			spec.cnf = &holder
		}
		return buildWire(t, spec)
	}
	x5cSigned := func(spec testWire) string {
		spec.signingKey = chain.leafKey
		if spec.x5c == nil {
			spec.x5c = chain.leafOnlyX5C()
		}
		spec.cnf = &holder
		return buildWire(t, spec)
	}
	disclosed := map[string]string{"given_name": "Erika"}

	cases := []struct {
		name     string
		profile  profile.Profile
		policy   Policy
		accepted string
		rejected string
		sentinel error
	}{
		{"parse", profile.Final, resolvingPolicy, signed(testWire{}), "this-is-not-a-credential", ErrCredentialParse},
		{"typ", profile.Final, resolvingPolicy, signed(testWire{typ: "vc+sd-jwt"}), signed(testWire{typ: "JWT"}), ErrCredentialTypInvalid},
		{"alg", profile.Final, resolvingPolicy, signed(testWire{}), unsignedWire(t, "none"), ErrCredentialAlgUnsupported},
		{"holder binding missing", profile.Final, bindingPolicy, signed(testWire{}), buildWire(t, testWire{signingKey: issuerKey, kid: "issuer-key-1"}), ErrHolderBindingMissing},
		{"holder binding mismatch", profile.Final, resolvingPolicy, signed(testWire{}), signed(testWire{cnf: &otherHolder}), ErrHolderBindingMismatch},
		{"issuer key unresolved", profile.Final, resolvingPolicy, signed(testWire{}), signed(testWire{signingKey: issuerKey, kid: "another-key"}), ErrIssuerKeyUnresolved},
		{"issuer signature invalid", profile.Final, resolvingPolicy, signed(testWire{}), signed(testWire{tamperSignature: true}), ErrIssuerSignatureInvalid},
		{"expired", profile.Final, resolvingPolicy, signed(testWire{}), signed(testWire{exp: time.Now().Add(-time.Hour)}), ErrCredentialExpired},
		{"not yet valid", profile.Final, resolvingPolicy, signed(testWire{}), signed(testWire{nbf: ptr(time.Now().Add(time.Hour))}), ErrCredentialNotYetValid},
		{"disclosure integrity", profile.Final, resolvingPolicy, signed(testWire{disclosures: disclosed}), signed(testWire{disclosures: disclosed, extraDisclosure: true}), ErrDisclosureIntegrity},
		{"sd_alg", profile.Final, resolvingPolicy, signed(testWire{disclosures: disclosed}), signed(testWire{disclosures: disclosed, sdAlg: "sha-1"}), ErrSDAlgUnsupported},
		{"issuer DNS binding", profile.Final, x509Trust(chain.anchors(), true), x5cSigned(testWire{}), x5cSigned(testWire{issuer: "https://other.example.test"}), ErrIssuerDNSBindingFailed},
		{"HAIP x5c required", profile.HAIP, x509Trust(chain.anchors(), false), x5cSigned(testWire{}), signed(testWire{}), ErrHAIPX5CRequired},
		{"HAIP trust anchor in x5c", profile.HAIP, x509Trust(chain.anchors(), false), x5cSigned(testWire{}), x5cSigned(testWire{x5c: chain.x5c()}), ErrHAIPTrustAnchorInX5C},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			acceptor := newTestAcceptor(t, testCase.profile)
			parsed, verification, err := acceptor.Verify(t.Context(), []byte(testCase.accepted), testCase.policy, sdJWT(&holder))
			require.NoError(t, err, "the control credential must be accepted")
			require.NotNil(t, parsed)
			require.NotNil(t, verification)

			_, _, err = acceptor.Verify(t.Context(), []byte(testCase.rejected), testCase.policy, sdJWT(&holder))
			require.ErrorIs(t, err, testCase.sentinel)
		})
	}
}

// TestVerifyPolicyIsPerCall pins that one acceptor judges a credential by the
// policy passed with each call.
func TestVerifyPolicyIsPerCall(t *testing.T) {
	acceptor := newTestAcceptor(t, profile.Final)
	holder := newHolderKey(t)
	issuerKey := testutil.NewP256Key(t)
	wire := []byte(buildWire(t, testWire{signingKey: issuerKey, kid: "issuer-key-1", cnf: &holder}))
	trusting := resolving(jose.JSONWebKey{Key: &issuerKey.PublicKey, KeyID: "issuer-key-1", Algorithm: "ES256"})

	first, verification, err := acceptor.Verify(t.Context(), wire, trusting, sdJWT(&holder))
	require.NoError(t, err)
	require.Equal(t, "issuer-key-1", verification.IssuerKeyID)

	_, again, err := acceptor.Verify(t.Context(), wire, trusting, sdJWT(&holder))
	require.NoError(t, err)
	require.Equal(t, verification, again)
	require.NotNil(t, first)

	_, _, err = acceptor.Verify(t.Context(), wire, Policy{}, sdJWT(&holder))
	require.ErrorIs(t, err, ErrIssuerKeyUnresolved)

	expiring := trusting
	expiring.Now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	_, _, err = acceptor.Verify(t.Context(), wire, expiring, sdJWT(&holder))
	require.ErrorIs(t, err, ErrCredentialExpired)
}

// TestVerifyRequireHolderBinding pins the fail-closed reading: a cnf is bound
// only once compared with a holder key.
func TestVerifyRequireHolderBinding(t *testing.T) {
	acceptor := newTestAcceptor(t, profile.Final)
	holder := newHolderKey(t)
	issuerKey := testutil.NewP256Key(t)
	bound := []byte(buildWire(t, testWire{signingKey: issuerKey, kid: "issuer-key-1", cnf: &holder}))
	unbound := []byte(buildWire(t, testWire{signingKey: issuerKey, kid: "issuer-key-1"}))
	optional := resolving(jose.JSONWebKey{Key: &issuerKey.PublicKey, KeyID: "issuer-key-1", Algorithm: "ES256"})
	requiring := optional
	requiring.RequireHolderBinding = true

	_, verification, err := acceptor.Verify(t.Context(), bound, requiring, sdJWT(&holder))
	require.NoError(t, err)
	require.True(t, verification.HolderBound)

	_, _, err = acceptor.Verify(t.Context(), bound, requiring, Options{})
	require.ErrorIs(t, err, ErrHolderBindingMissing)

	_, _, err = acceptor.Verify(t.Context(), unbound, requiring, sdJWT(&holder))
	require.ErrorIs(t, err, ErrHolderBindingMissing)

	_, verification, err = acceptor.Verify(t.Context(), bound, optional, Options{})
	require.NoError(t, err)
	require.False(t, verification.HolderBound)
}

func TestVerifyExpectedSDJWTVCType(t *testing.T) {
	acceptor := newTestAcceptor(t, profile.Final)
	issuerKey := testutil.NewP256Key(t)
	wire := []byte(buildWire(t, testWire{signingKey: issuerKey, kid: "issuer-key-1", vct: "urn:test:acceptance"}))
	policy := resolving(jose.JSONWebKey{Key: &issuerKey.PublicKey, KeyID: "issuer-key-1", Algorithm: "ES256"})

	for expected, want := range map[string]error{"urn:test:acceptance": nil, "urn:test:other": ErrCredentialTypInvalid, "": nil} {
		policy.ExpectedSDJWTVCType = expected
		_, _, err := acceptor.Verify(t.Context(), wire, policy, Options{})
		if want == nil {
			require.NoError(t, err, "expected vct %q", expected)
		} else {
			require.ErrorIs(t, err, want)
		}
	}
}

func TestVerifyInfersTheFlavor(t *testing.T) {
	acceptor := newTestAcceptor(t, profile.Final)
	issuerKey := testutil.NewP256Key(t)
	wire := []byte(buildWire(t, testWire{signingKey: issuerKey, typ: "JWT"}))
	// With the flavor inferred, the SD-JWT VC typ rule applies to a "~" wire.
	_, _, err := acceptor.Verify(t.Context(), wire, Policy{UnverifiedIssuer: true}, Options{})
	require.ErrorIs(t, err, ErrCredentialTypInvalid)
	require.Equal(t, credential.SDJwtVC, inferredFlavor(wire))
	require.Equal(t, credential.JwtVc, inferredFlavor([]byte("a.b.c")))
}

func TestIssuerSignedJOSEHeader(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"dc+sd-jwt"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"vct":"https://example/pid"}`))

	got, err := IssuerSignedJOSEHeader(credential.SDJwtVC, []byte(header+"."+payload+".signature~disclosure"))
	require.NoError(t, err)
	require.Equal(t, "dc+sd-jwt", got["typ"])

	got, err = IssuerSignedJOSEHeader(credential.JwtVc, []byte(header+"."+payload+".signature"))
	require.NoError(t, err)
	require.Equal(t, "ES256", got["alg"])

	for name, raw := range map[string]string{
		"not a compact JWS":     "not-a-jwt",
		"header not base64url":  "!!!." + payload + ".signature",
		"header not JSON":       base64.RawURLEncoding.EncodeToString([]byte("not json")) + "." + payload + ".signature",
		"too many JWS segments": header + "." + payload + ".sig.extra",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := IssuerSignedJOSEHeader(credential.JwtVc, []byte(raw))
			require.ErrorIs(t, err, ErrCredentialParse)
		})
	}
}

func TestNewAcceptorValidatesInputs(t *testing.T) {
	serialization, err := serializer.NewSerializationDispatcher(serializer.WithDefaultConfig())
	require.NoError(t, err)
	verification, err := verifier.NewVerificationDispatcher(verifier.WithDefaultConfig())
	require.NoError(t, err)

	_, err = NewAcceptor(profile.Final, nil, verification)
	require.ErrorContains(t, err, "serialization dispatcher")
	_, err = NewAcceptor(profile.Final, serialization, nil)
	require.ErrorContains(t, err, "verification dispatcher")
	_, err = NewAcceptor(profile.Profile("draft24"), serialization, verification)
	require.Error(t, err)

	acceptor, err := NewAcceptor(profile.Profile(""), serialization, verification)
	require.NoError(t, err)
	require.Equal(t, profile.Final, acceptor.profile)
}
