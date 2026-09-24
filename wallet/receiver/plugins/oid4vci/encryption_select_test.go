package oid4vci

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"

	"github.com/trustknots/vcknots/wallet/receiver/types"
)

func requestEncryptionMetadata(enc []string, keys ...jose.JSONWebKey) *types.CredentialIssuerMetadata {
	return &types.CredentialIssuerMetadata{
		CredentialRequestEncryption: &types.CredentialRequestEncryption{
			Jwks:               jose.JSONWebKeySet{Keys: keys},
			EncValuesSupported: enc,
		},
	}
}

// Section 12.2.4 enc_values_supported lists what the issuer can decrypt; the
// wallet uses the first entry it can produce, as the response side does.
func TestCredentialRequestEncryptionUsesTheFirstSupportedEnc(t *testing.T) {
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	metadata := requestEncryptionMetadata([]string{"XC20P", "A256GCM"},
		jose.JSONWebKey{Key: issuerKey.Public(), KeyID: "enc-1", Algorithm: "ECDH-ES", Use: "enc"})

	body, contentType, err := (&Oid4vciReceiver{}).EncodeCredentialRequest(map[string]any{"credential_configuration_id": "pid"}, metadata)
	if err != nil {
		t.Fatalf("EncodeCredentialRequest() error = %v", err)
	}
	if contentType != "application/jwt" {
		t.Fatalf("Content-Type = %q", contentType)
	}
	jwe, err := jose.ParseEncrypted(string(body), []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		t.Fatalf("request is not an A256GCM JWE: %v", err)
	}
	if got := jwe.Header.ExtraHeaders["enc"]; got != "A256GCM" {
		t.Fatalf("enc = %v, want A256GCM", got)
	}
}

// ECDH-ES needs an EC key (RFC 7518 Section 4.6). Ed25519 is a signature curve,
// so a key of that type is refused with an error that names it.
func TestCredentialRequestEncryptionRefusesEd25519Keys(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string]jose.JSONWebKey{
		"without alg": {Key: public, KeyID: "okp-1", Use: "enc"},
		"with alg":    {Key: public, KeyID: "okp-1", Use: "enc", Algorithm: "ECDH-ES"},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := (&Oid4vciReceiver{}).EncodeCredentialRequest(map[string]any{}, requestEncryptionMetadata([]string{"A128GCM"}, key))
			if err == nil || !strings.Contains(err.Error(), "Ed25519") {
				t.Fatalf("err = %v, want an error naming the Ed25519 key", err)
			}
		})
	}
}

// Section 10: "The `alg` parameter MUST be present. The JWE `alg` algorithm
// used MUST be equal to the `alg` value of the chosen JWK." The response key
// therefore carries an alg, taken from alg_values_supported (Section 12.2.4).
func TestCredentialResponseEncryptionHonoursAlgValuesSupported(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	metadata := func(algs ...string) *types.CredentialIssuerMetadata {
		return &types.CredentialIssuerMetadata{CredentialResponseEncryption: &types.CredentialResponseEncryption{
			AlgValuesSupported: algs,
			EncValuesSupported: []string{"A128GCM"},
		}}
	}
	jwkAlg := func(t *testing.T, params map[string]any) string {
		t.Helper()
		jwk, ok := params["jwk"].(jose.JSONWebKey)
		if !ok {
			t.Fatalf("jwk = %#v", params["jwk"])
		}
		return jwk.Algorithm
	}

	t.Run("an EC key without alg takes the first EC algorithm listed", func(t *testing.T) {
		params, err := CredentialResponseEncryptionParameters(metadata("RSA-OAEP-256", "ECDH-ES+A128KW", "ECDH-ES"), &jose.JSONWebKey{Key: &ecKey.PublicKey})
		if err != nil {
			t.Fatal(err)
		}
		if got := jwkAlg(t, params); got != "ECDH-ES+A128KW" {
			t.Fatalf("jwk alg = %q", got)
		}
	})
	t.Run("an RSA key without alg takes RSA-OAEP-256", func(t *testing.T) {
		params, err := CredentialResponseEncryptionParameters(metadata("ECDH-ES", "RSA-OAEP-256"), &jose.JSONWebKey{Key: &rsaKey.PublicKey})
		if err != nil {
			t.Fatal(err)
		}
		if got := jwkAlg(t, params); got != "RSA-OAEP-256" {
			t.Fatalf("jwk alg = %q", got)
		}
	})
	t.Run("a key alg the issuer does not list is refused", func(t *testing.T) {
		if _, err := CredentialResponseEncryptionParameters(metadata("ECDH-ES"), &jose.JSONWebKey{Key: &ecKey.PublicKey, Algorithm: "ECDH-ES+A256KW"}); err == nil {
			t.Fatal("expected an error")
		}
	})
	t.Run("a key with no listed algorithm it can use is refused", func(t *testing.T) {
		if _, err := CredentialResponseEncryptionParameters(metadata("RSA-OAEP-256"), &jose.JSONWebKey{Key: &ecKey.PublicKey}); err == nil {
			t.Fatal("expected an error")
		}
	})
	t.Run("an issuer that lists no alg takes the key type's default", func(t *testing.T) {
		params, err := CredentialResponseEncryptionParameters(metadata(), &jose.JSONWebKey{Key: &ecKey.PublicKey})
		if err != nil {
			t.Fatal(err)
		}
		if got := jwkAlg(t, params); got != "ECDH-ES" {
			t.Fatalf("jwk alg = %q", got)
		}
	})
}
