package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func signCompact(t *testing.T, algorithm jose.SignatureAlgorithm, key any) *jose.JSONWebSignature {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: algorithm, Key: key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	object, err := signer.Sign([]byte(`{"sub":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	compact, err := object.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := jose.ParseSignedCompact(compact, AcceptedSignatureAlgorithms())
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestVerifySignatureRefusesShortRSAKeys(t *testing.T) {
	short, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	// RFC 7518 Section 3.3: "A key of size 2048 bits or larger MUST be used".
	for _, algorithm := range []jose.SignatureAlgorithm{jose.RS256, jose.PS256} {
		signed := signCompact(t, algorithm, short)
		for name, key := range map[string]any{
			"pointer":     &short.PublicKey,
			"value":       short.PublicKey,
			"jwk":         jose.JSONWebKey{Key: &short.PublicKey},
			"jwk pointer": &jose.JSONWebKey{Key: &short.PublicKey},
			"private":     short,
		} {
			t.Run(string(algorithm)+"/"+name, func(t *testing.T) {
				payload, err := VerifySignature(signed, key)
				if !errors.Is(err, ErrVerificationKeyTooWeak) || payload != nil {
					t.Fatalf("VerifySignature = %q, %v; want ErrVerificationKeyTooWeak", payload, err)
				}
			})
		}
	}
}

func TestVerifySignatureAcceptsSufficientKeys(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, MinimumRSAModulusBits)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		algorithm jose.SignatureAlgorithm
		signing   any
		verifying any
	}{
		"RSA 2048":  {jose.RS256, rsaKey, &rsaKey.PublicKey},
		"RSA-PSS":   {jose.PS256, rsaKey, jose.JSONWebKey{Key: &rsaKey.PublicKey}},
		"ECDSA":     {jose.ES256, ecKey, &ecKey.PublicKey},
		"ECDSA JWK": {jose.ES256, ecKey, &jose.JSONWebKey{Key: &ecKey.PublicKey}},
	} {
		t.Run(name, func(t *testing.T) {
			payload, err := VerifySignature(signCompact(t, test.algorithm, test.signing), test.verifying)
			if err != nil || string(payload) != `{"sub":"x"}` {
				t.Fatalf("VerifySignature = %q, %v", payload, err)
			}
		})
	}
}

func TestRequireVerificationKeyStrengthRefusesAnRSAKeyWithoutModulus(t *testing.T) {
	if err := RequireVerificationKeyStrength(&rsa.PublicKey{E: 65537}); !errors.Is(err, ErrVerificationKeyTooWeak) {
		t.Fatalf("err = %v", err)
	}
}

func TestRequireVerificationKeyStrengthChecksEveryKeyOfASet(t *testing.T) {
	short, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// go-jose picks the key of a set by the header kid, so a set is only as
	// strong as its weakest key.
	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &ecKey.PublicKey}, {Key: &short.PublicKey}}}
	for name, key := range map[string]any{"value": set, "pointer": &set} {
		if err := RequireVerificationKeyStrength(key); !errors.Is(err, ErrVerificationKeyTooWeak) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
	if err := RequireVerificationKeyStrength(jose.JSONWebKeySet{Keys: set.Keys[:1]}); err != nil {
		t.Fatalf("strong set: err = %v", err)
	}
}

func signMulti(t *testing.T, key any) *jose.JSONWebSignature {
	t.Helper()
	signer, err := jose.NewMultiSigner([]jose.SigningKey{{Algorithm: jose.RS256, Key: key}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	object, err := signer.Sign([]byte(`{"sub":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := jose.ParseSignedJSON(object.FullSerialize(), AcceptedSignatureAlgorithms())
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestVerifyMultiSignatureAppliesTheRSAFloor(t *testing.T) {
	short, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	strong, err := rsa.GenerateKey(rand.Reader, MinimumRSAModulusBits)
	if err != nil {
		t.Fatal(err)
	}
	index, _, payload, err := VerifyMultiSignature(signMulti(t, short), &short.PublicKey)
	if !errors.Is(err, ErrVerificationKeyTooWeak) || payload != nil || index != -1 {
		t.Fatalf("VerifyMultiSignature(1024) = %d, %q, %v; want ErrVerificationKeyTooWeak", index, payload, err)
	}
	index, _, payload, err = VerifyMultiSignature(signMulti(t, strong), &strong.PublicKey)
	if err != nil || index != 0 || string(payload) != `{"sub":"x"}` {
		t.Fatalf("VerifyMultiSignature(2048) = %d, %q, %v", index, payload, err)
	}
}

func signedToken(t *testing.T, key any) *jwt.JSONWebToken {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := jwt.Signed(signer).Claims(map[string]any{"sub": "x"}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwt.ParseSigned(compact, AcceptedSignatureAlgorithms())
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestVerifyClaimsAppliesTheRSAFloor(t *testing.T) {
	short, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	strong, err := rsa.GenerateKey(rand.Reader, MinimumRSAModulusBits)
	if err != nil {
		t.Fatal(err)
	}
	var refused map[string]any
	if err := VerifyClaims(signedToken(t, short), jose.JSONWebKey{Key: &short.PublicKey}, &refused); !errors.Is(err, ErrVerificationKeyTooWeak) || refused != nil {
		t.Fatalf("VerifyClaims(1024) = %v, %v; want ErrVerificationKeyTooWeak", refused, err)
	}
	var claims map[string]any
	if err := VerifyClaims(signedToken(t, strong), &strong.PublicKey, &claims); err != nil || claims["sub"] != "x" {
		t.Fatalf("VerifyClaims(2048) = %v, %v", claims, err)
	}
	other, err := rsa.GenerateKey(rand.Reader, MinimumRSAModulusBits)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyClaims(signedToken(t, strong), &other.PublicKey, &claims); err == nil || errors.Is(err, ErrVerificationKeyTooWeak) {
		t.Fatalf("VerifyClaims(wrong key) = %v; want a signature error", err)
	}
}
