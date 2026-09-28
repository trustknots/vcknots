package signature

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"math/big"
	"sync"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/verifier/types"
)

var (
	rsaKeyOnce sync.Once
	rsaKey2048 *rsa.PrivateKey
	rsaKey1024 *rsa.PrivateKey
)

// testRSAKeys generates the RSA keys once: a 2048 bit key that satisfies
// MinimumRSAModulusBits and a 1024 bit key that does not.
func testRSAKeys(t *testing.T) (*rsa.PrivateKey, *rsa.PrivateKey) {
	t.Helper()
	rsaKeyOnce.Do(func() {
		var err error
		rsaKey2048, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic("failed to generate 2048 bit RSA key: " + err.Error())
		}
		rsaKey1024, err = rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			panic("failed to generate 1024 bit RSA key: " + err.Error())
		}
	})
	return rsaKey2048, rsaKey1024
}

func ecdsaProof(t *testing.T, key *ecdsa.PrivateKey, algorithm jose.SignatureAlgorithm, digest crypto.Hash, payload []byte) credential.CredentialProof {
	t.Helper()
	hasher := digest.New()
	hasher.Write(payload)
	r, s, err := ecdsa.Sign(rand.Reader, key, hasher.Sum(nil))
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	size := (key.Curve.Params().BitSize + 7) / 8
	raw := make([]byte, size*2)
	r.FillBytes(raw[:size])
	s.FillBytes(raw[size:])
	return credential.CredentialProof{Algorithm: algorithm, Signature: raw, Payload: payload}
}

func TestECDSA_VerifiesEveryCurve(t *testing.T) {
	cases := []struct {
		algorithm jose.SignatureAlgorithm
		curve     elliptic.Curve
		digest    crypto.Hash
	}{
		{jose.ES256, elliptic.P256(), crypto.SHA256},
		{jose.ES384, elliptic.P384(), crypto.SHA384},
		{jose.ES512, elliptic.P521(), crypto.SHA512},
	}
	payload := []byte("test message for signature")
	for _, testCase := range cases {
		t.Run(string(testCase.algorithm), func(t *testing.T) {
			key, err := ecdsa.GenerateKey(testCase.curve, rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate key: %v", err)
			}
			publicKey := &jose.JSONWebKey{Key: &key.PublicKey, Algorithm: string(testCase.algorithm)}
			proof := ecdsaProof(t, key, testCase.algorithm, testCase.digest, payload)

			valid, err := ECDSA(&proof, publicKey, testCase.algorithm, testCase.curve, testCase.digest)
			if err != nil || !valid {
				t.Fatalf("ECDSA() = %v, %v; want true, nil", valid, err)
			}

			// The value form a JWK may carry verifies identically.
			valid, err = ECDSA(&proof, &jose.JSONWebKey{Key: key.PublicKey}, testCase.algorithm, testCase.curve, testCase.digest)
			if err != nil || !valid {
				t.Fatalf("ECDSA() with a value key = %v, %v; want true, nil", valid, err)
			}

			tampered := proof
			tampered.Payload = []byte("tampered message")
			if _, err := ECDSA(&tampered, publicKey, testCase.algorithm, testCase.curve, testCase.digest); !errors.Is(err, types.ErrVerificationFailed) {
				t.Errorf("ECDSA() on a tampered payload = %v; want ErrVerificationFailed", err)
			}
		})
	}
}

func TestECDSA_RejectsWrongCurveForAlgorithm(t *testing.T) {
	// Every curve is offered to every other algorithm: a P-256 key must not
	// verify an ES384 proof even though both are ECDSA keys.
	cases := []struct {
		algorithm jose.SignatureAlgorithm
		curve     elliptic.Curve
		digest    crypto.Hash
	}{
		{jose.ES256, elliptic.P256(), crypto.SHA256},
		{jose.ES384, elliptic.P384(), crypto.SHA384},
		{jose.ES512, elliptic.P521(), crypto.SHA512},
	}
	payload := []byte("test message for signature")
	for _, signing := range cases {
		for _, verifying := range cases {
			if signing.algorithm == verifying.algorithm {
				continue
			}
			t.Run(string(signing.algorithm)+"-key-for-"+string(verifying.algorithm), func(t *testing.T) {
				key, err := ecdsa.GenerateKey(signing.curve, rand.Reader)
				if err != nil {
					t.Fatalf("failed to generate key: %v", err)
				}
				proof := ecdsaProof(t, key, verifying.algorithm, verifying.digest, payload)
				_, err = ECDSA(&proof, &jose.JSONWebKey{Key: &key.PublicKey}, verifying.algorithm, verifying.curve, verifying.digest)
				if !errors.Is(err, types.ErrInvalidPublicKey) {
					t.Fatalf("ECDSA() = %v; want ErrInvalidPublicKey", err)
				}
			})
		}
	}
}

func TestECDSA_RejectsMalformedInput(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	publicKey := &jose.JSONWebKey{Key: &key.PublicKey}
	payload := []byte("test message for signature")
	valid := ecdsaProof(t, key, jose.ES256, crypto.SHA256, payload)

	t.Run("nil proof", func(t *testing.T) {
		if _, err := ECDSA(nil, publicKey, jose.ES256, elliptic.P256(), crypto.SHA256); !errors.Is(err, types.ErrInvalidProof) {
			t.Errorf("ECDSA() = %v; want ErrInvalidProof", err)
		}
	})

	t.Run("algorithm mismatch", func(t *testing.T) {
		mismatched := valid
		mismatched.Algorithm = jose.ES384
		if _, err := ECDSA(&mismatched, publicKey, jose.ES256, elliptic.P256(), crypto.SHA256); !errors.Is(err, types.ErrUnsupportedAlgorithm) {
			t.Errorf("ECDSA() = %v; want ErrUnsupportedAlgorithm", err)
		}
	})

	t.Run("nil public key", func(t *testing.T) {
		if _, err := ECDSA(&valid, nil, jose.ES256, elliptic.P256(), crypto.SHA256); !errors.Is(err, types.ErrInvalidPublicKey) {
			t.Errorf("ECDSA() = %v; want ErrInvalidPublicKey", err)
		}
	})

	t.Run("key of another type", func(t *testing.T) {
		rsaPrivate, _ := testRSAKeys(t)
		if _, err := ECDSA(&valid, &jose.JSONWebKey{Key: &rsaPrivate.PublicKey}, jose.ES256, elliptic.P256(), crypto.SHA256); !errors.Is(err, types.ErrInvalidPublicKey) {
			t.Errorf("ECDSA() = %v; want ErrInvalidPublicKey", err)
		}
	})

	t.Run("empty payload", func(t *testing.T) {
		empty := valid
		empty.Payload = nil
		if _, err := ECDSA(&empty, publicKey, jose.ES256, elliptic.P256(), crypto.SHA256); !errors.Is(err, types.ErrInvalidPayload) {
			t.Errorf("ECDSA() = %v; want ErrInvalidPayload", err)
		}
	})

	t.Run("signature length", func(t *testing.T) {
		short := valid
		short.Signature = valid.Signature[:63]
		if _, err := ECDSA(&short, publicKey, jose.ES256, elliptic.P256(), crypto.SHA256); !errors.Is(err, types.ErrInvalidSignature) {
			t.Errorf("ECDSA() = %v; want ErrInvalidSignature", err)
		}
	})

	t.Run("DER signature is not accepted", func(t *testing.T) {
		der, err := ecdsa.SignASN1(rand.Reader, key, hashPayload(crypto.SHA256, payload))
		if err != nil {
			t.Fatalf("failed to sign: %v", err)
		}
		proof := credential.CredentialProof{Algorithm: jose.ES256, Signature: der, Payload: payload}
		if _, err := ECDSA(&proof, publicKey, jose.ES256, elliptic.P256(), crypto.SHA256); err == nil {
			t.Error("ECDSA() should reject a DER encoded signature")
		}
	})

	t.Run("zero R and S", func(t *testing.T) {
		zeroed := valid
		zeroed.Signature = make([]byte, 64)
		if _, err := ECDSA(&zeroed, publicKey, jose.ES256, elliptic.P256(), crypto.SHA256); !errors.Is(err, types.ErrVerificationFailed) {
			t.Errorf("ECDSA() = %v; want ErrVerificationFailed", err)
		}
	})

	t.Run("curveless key", func(t *testing.T) {
		if _, err := ECDSA(&valid, &jose.JSONWebKey{Key: &ecdsa.PublicKey{X: big.NewInt(1), Y: big.NewInt(1)}}, jose.ES256, elliptic.P256(), crypto.SHA256); !errors.Is(err, types.ErrInvalidPublicKey) {
			t.Errorf("ECDSA() = %v; want ErrInvalidPublicKey", err)
		}
	})
}

func TestRSA_VerifiesEveryDigestAndScheme(t *testing.T) {
	private, _ := testRSAKeys(t)
	publicKey := &jose.JSONWebKey{Key: &private.PublicKey}
	payload := []byte("test message for signature")

	cases := []struct {
		algorithm jose.SignatureAlgorithm
		digest    crypto.Hash
		pss       bool
	}{
		{jose.RS256, crypto.SHA256, false},
		{jose.RS384, crypto.SHA384, false},
		{jose.RS512, crypto.SHA512, false},
		{jose.PS256, crypto.SHA256, true},
		{jose.PS384, crypto.SHA384, true},
		{jose.PS512, crypto.SHA512, true},
	}
	for _, testCase := range cases {
		t.Run(string(testCase.algorithm), func(t *testing.T) {
			hashed := hashPayload(testCase.digest, payload)
			var (
				raw []byte
				err error
			)
			if testCase.pss {
				raw, err = rsa.SignPSS(rand.Reader, private, testCase.digest, hashed, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: testCase.digest})
			} else {
				raw, err = rsa.SignPKCS1v15(rand.Reader, private, testCase.digest, hashed)
			}
			if err != nil {
				t.Fatalf("failed to sign: %v", err)
			}
			proof := credential.CredentialProof{Algorithm: testCase.algorithm, Signature: raw, Payload: payload}

			verify := RSAPKCS1v15
			other := RSAPSS
			if testCase.pss {
				verify, other = RSAPSS, RSAPKCS1v15
			}

			valid, err := verify(&proof, publicKey, testCase.algorithm, testCase.digest)
			if err != nil || !valid {
				t.Fatalf("verify() = %v, %v; want true, nil", valid, err)
			}

			// The padding scheme is part of the algorithm: a PSS signature
			// must not verify as PKCS1v15 and the reverse.
			if _, err := other(&proof, publicKey, testCase.algorithm, testCase.digest); !errors.Is(err, types.ErrVerificationFailed) {
				t.Errorf("the other padding scheme accepted the signature: %v", err)
			}

			tampered := proof
			tampered.Payload = []byte("tampered message")
			if _, err := verify(&tampered, publicKey, testCase.algorithm, testCase.digest); !errors.Is(err, types.ErrVerificationFailed) {
				t.Errorf("verify() on a tampered payload = %v; want ErrVerificationFailed", err)
			}
		})
	}
}

func TestRSA_RejectsModulusBelowMinimum(t *testing.T) {
	_, weak := testRSAKeys(t)
	payload := []byte("test message for signature")
	hashed := hashPayload(crypto.SHA256, payload)

	pkcs1, err := rsa.SignPKCS1v15(rand.Reader, weak, crypto.SHA256, hashed)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	pss, err := rsa.SignPSS(rand.Reader, weak, crypto.SHA256, hashed, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	publicKey := &jose.JSONWebKey{Key: &weak.PublicKey}

	// The signatures are cryptographically correct: only the key size is
	// refused, so the 1024 bit key is rejected before any verification.
	if _, err := RSAPKCS1v15(&credential.CredentialProof{Algorithm: jose.RS256, Signature: pkcs1, Payload: payload}, publicKey, jose.RS256, crypto.SHA256); !errors.Is(err, types.ErrInvalidPublicKey) {
		t.Errorf("RSAPKCS1v15() = %v; want ErrInvalidPublicKey", err)
	}
	if _, err := RSAPSS(&credential.CredentialProof{Algorithm: jose.PS256, Signature: pss, Payload: payload}, publicKey, jose.PS256, crypto.SHA256); !errors.Is(err, types.ErrInvalidPublicKey) {
		t.Errorf("RSAPSS() = %v; want ErrInvalidPublicKey", err)
	}
}

func TestRSA_RejectsMalformedInput(t *testing.T) {
	private, _ := testRSAKeys(t)
	publicKey := &jose.JSONWebKey{Key: &private.PublicKey}
	payload := []byte("test message for signature")
	raw, err := rsa.SignPKCS1v15(rand.Reader, private, crypto.SHA256, hashPayload(crypto.SHA256, payload))
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	valid := credential.CredentialProof{Algorithm: jose.RS256, Signature: raw, Payload: payload}

	t.Run("algorithm mismatch", func(t *testing.T) {
		mismatched := valid
		mismatched.Algorithm = jose.RS512
		if _, err := RSAPKCS1v15(&mismatched, publicKey, jose.RS256, crypto.SHA256); !errors.Is(err, types.ErrUnsupportedAlgorithm) {
			t.Errorf("RSAPKCS1v15() = %v; want ErrUnsupportedAlgorithm", err)
		}
	})

	t.Run("key of another type", func(t *testing.T) {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}
		if _, err := RSAPKCS1v15(&valid, &jose.JSONWebKey{Key: &ecKey.PublicKey}, jose.RS256, crypto.SHA256); !errors.Is(err, types.ErrInvalidPublicKey) {
			t.Errorf("RSAPKCS1v15() = %v; want ErrInvalidPublicKey", err)
		}
	})

	t.Run("modulus missing", func(t *testing.T) {
		if _, err := RSAPKCS1v15(&valid, &jose.JSONWebKey{Key: &rsa.PublicKey{E: 65537}}, jose.RS256, crypto.SHA256); !errors.Is(err, types.ErrInvalidPublicKey) {
			t.Errorf("RSAPKCS1v15() = %v; want ErrInvalidPublicKey", err)
		}
	})

	t.Run("empty signature", func(t *testing.T) {
		empty := valid
		empty.Signature = nil
		if _, err := RSAPKCS1v15(&empty, publicKey, jose.RS256, crypto.SHA256); !errors.Is(err, types.ErrInvalidSignature) {
			t.Errorf("RSAPKCS1v15() = %v; want ErrInvalidSignature", err)
		}
	})

	t.Run("digest mismatch", func(t *testing.T) {
		// The same signature offered as RS512 must not verify: the digest is
		// part of the algorithm.
		relabelled := valid
		relabelled.Algorithm = jose.RS512
		if _, err := RSAPKCS1v15(&relabelled, publicKey, jose.RS512, crypto.SHA512); !errors.Is(err, types.ErrVerificationFailed) {
			t.Errorf("RSAPKCS1v15() = %v; want ErrVerificationFailed", err)
		}
	})

	t.Run("value form of the key", func(t *testing.T) {
		if valid, err := RSAPKCS1v15(&valid, &jose.JSONWebKey{Key: private.PublicKey}, jose.RS256, crypto.SHA256); err != nil || !valid {
			t.Errorf("RSAPKCS1v15() = %v, %v; want true, nil", valid, err)
		}
	})
}

func TestEd25519(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	payload := []byte("test message for signature")
	proof := credential.CredentialProof{
		Algorithm: jose.EdDSA,
		Signature: ed25519.Sign(private, payload),
		Payload:   payload,
	}

	t.Run("valid signature", func(t *testing.T) {
		if valid, err := Ed25519(&proof, &jose.JSONWebKey{Key: public}); err != nil || !valid {
			t.Fatalf("Ed25519() = %v, %v; want true, nil", valid, err)
		}
		if valid, err := Ed25519(&proof, &jose.JSONWebKey{Key: &public}); err != nil || !valid {
			t.Fatalf("Ed25519() with a pointer key = %v, %v; want true, nil", valid, err)
		}
	})

	t.Run("tampered payload", func(t *testing.T) {
		tampered := proof
		tampered.Payload = []byte("tampered message")
		if _, err := Ed25519(&tampered, &jose.JSONWebKey{Key: public}); !errors.Is(err, types.ErrVerificationFailed) {
			t.Errorf("Ed25519() = %v; want ErrVerificationFailed", err)
		}
	})

	t.Run("algorithm mismatch", func(t *testing.T) {
		mismatched := proof
		mismatched.Algorithm = jose.ES256
		if _, err := Ed25519(&mismatched, &jose.JSONWebKey{Key: public}); !errors.Is(err, types.ErrUnsupportedAlgorithm) {
			t.Errorf("Ed25519() = %v; want ErrUnsupportedAlgorithm", err)
		}
	})

	t.Run("key of another type", func(t *testing.T) {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}
		if _, err := Ed25519(&proof, &jose.JSONWebKey{Key: &ecKey.PublicKey}); !errors.Is(err, types.ErrInvalidPublicKey) {
			t.Errorf("Ed25519() = %v; want ErrInvalidPublicKey", err)
		}
	})

	t.Run("truncated key", func(t *testing.T) {
		if _, err := Ed25519(&proof, &jose.JSONWebKey{Key: ed25519.PublicKey(public[:16])}); !errors.Is(err, types.ErrInvalidPublicKey) {
			t.Errorf("Ed25519() = %v; want ErrInvalidPublicKey", err)
		}
	})

	t.Run("signature length", func(t *testing.T) {
		short := proof
		short.Signature = proof.Signature[:32]
		if _, err := Ed25519(&short, &jose.JSONWebKey{Key: public}); !errors.Is(err, types.ErrInvalidSignature) {
			t.Errorf("Ed25519() = %v; want ErrInvalidSignature", err)
		}
	})
}
