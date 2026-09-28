package jwtproof

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/trustknots/vcknots/wallet/keystore"
)

// hsmKey stands for a key held in a hardware module: it exposes only its public
// JWK and returns DER-encoded ECDSA signatures from Sign.
type hsmKey struct {
	private *ecdsa.PrivateKey
	kid     string
	alg     string
	signed  int
}

func newHSMKey(t *testing.T, curve elliptic.Curve) *hsmKey {
	t.Helper()
	private, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &hsmKey{private: private}
}

func (k *hsmKey) ID() string { return "hsm" }

func (k *hsmKey) PublicKey() jose.JSONWebKey {
	return jose.JSONWebKey{Key: &k.private.PublicKey, KeyID: k.kid, Algorithm: k.alg}
}

func (k *hsmKey) Sign(data []byte) ([]byte, error) {
	k.signed++
	hash := crypto.SHA256
	switch k.private.Curve {
	case elliptic.P384():
		hash = crypto.SHA384
	case elliptic.P521():
		hash = crypto.SHA512
	}
	digest := hash.New()
	digest.Write(data)
	return ecdsa.SignASN1(rand.Reader, k.private, digest.Sum(nil))
}

type ctxKey struct{}

// contextHSMKey also implements keystore.ContextSigner and records the context
// value it was called with.
type contextHSMKey struct {
	*hsmKey
	seen any
}

func (k *contextHSMKey) Sign([]byte) ([]byte, error) {
	return nil, errors.New("Sign must not be called on a ContextSigner")
}

func (k *contextHSMKey) SignContext(ctx context.Context, data []byte) ([]byte, error) {
	k.seen = ctx.Value(ctxKey{})
	return k.hsmKey.Sign(data)
}

type ed25519Key struct{ private ed25519.PrivateKey }

func (k ed25519Key) ID() string { return "ed" }
func (k ed25519Key) PublicKey() jose.JSONWebKey {
	return jose.JSONWebKey{Key: k.private.Public()}
}
func (k ed25519Key) Sign(data []byte) ([]byte, error) { return ed25519.Sign(k.private, data), nil }

type rsaKey struct {
	private *rsa.PrivateKey
	alg     string
}

func (k rsaKey) ID() string { return "rsa" }
func (k rsaKey) PublicKey() jose.JSONWebKey {
	return jose.JSONWebKey{Key: &k.private.PublicKey, Algorithm: k.alg}
}
func (k rsaKey) Sign(data []byte) ([]byte, error) {
	digest := sha256.Sum256(data)
	return rsa.SignPKCS1v15(rand.Reader, k.private, crypto.SHA256, digest[:])
}

// verify checks the signature against public and returns the protected header
// and the claims.
func verify(t *testing.T, token string, public any) (map[string]any, map[string]any) {
	t.Helper()
	signed, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256, jose.ES384, jose.ES512, jose.EdDSA, jose.RS256})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	payload, err := signed.Verify(public)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	rawHeader, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[0])
	if err != nil {
		t.Fatal(err)
	}
	var header map[string]any
	if err := json.Unmarshal(rawHeader, &header); err != nil {
		t.Fatal(err)
	}
	return header, claims
}

func requirePublicJWK(t *testing.T, value any) map[string]any {
	t.Helper()
	jwk, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("jwk member is %T, want an object", value)
	}
	if _, private := jwk["d"]; private {
		t.Fatal("jwk member carries private key material")
	}
	return jwk
}

func TestDPoPWithHSMKey(t *testing.T) {
	key := newHSMKey(t, elliptic.P256())
	key.kid = "hsm-kid"
	token, err := DPoP(context.Background(), key, DPoPOptions{
		Method:      "post",
		URL:         "https://as.example/token?x=1#frag",
		AccessToken: "at",
		Nonce:       "n-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	header, claims := verify(t, token, &key.private.PublicKey)
	if header["typ"] != TypeDPoP || header["alg"] != "ES256" {
		t.Fatalf("header = %v", header)
	}
	if _, found := header["kid"]; found {
		t.Fatal("DPoP proof must not carry a kid header")
	}
	jwk := requirePublicJWK(t, header["jwk"])
	if jwk["alg"] != "ES256" {
		t.Fatalf("jwk alg = %v", jwk["alg"])
	}
	ath := sha256.Sum256([]byte("at"))
	want := map[string]any{"htm": "POST", "htu": "https://as.example/token", "nonce": "n-1", "ath": base64.RawURLEncoding.EncodeToString(ath[:])}
	for name, value := range want {
		if claims[name] != value {
			t.Errorf("claim %s = %v, want %v", name, claims[name], value)
		}
	}
	if claims["jti"] == "" || claims["iat"] == nil {
		t.Fatalf("claims = %v", claims)
	}
}

func TestDPoPRejectsRelativeURL(t *testing.T) {
	if _, err := DPoP(context.Background(), newHSMKey(t, elliptic.P256()), DPoPOptions{Method: "GET", URL: "/token"}); err == nil {
		t.Fatal("a relative htu must be refused")
	}
}

func TestKeyProofBindings(t *testing.T) {
	key := newHSMKey(t, elliptic.P384())
	key.kid = "k1"

	token, err := KeyProof(context.Background(), key, KeyProofOptions{
		Audience:         "https://issuer.example",
		Issuer:           "client",
		Nonce:            "c-nonce",
		KeyAttestation:   "ka.jwt",
		SigningAlgValues: []jose.SignatureAlgorithm{jose.ES256, jose.ES384},
	})
	if err != nil {
		t.Fatal(err)
	}
	header, claims := verify(t, token, &key.private.PublicKey)
	if header["typ"] != TypeKeyProof || header["alg"] != "ES384" || header["key_attestation"] != "ka.jwt" {
		t.Fatalf("header = %v", header)
	}
	if _, found := header["kid"]; found {
		t.Fatal("a jwk-bound key proof must not carry a kid header (OpenID4VCI 1.0 Appendix F.1)")
	}
	requirePublicJWK(t, header["jwk"])
	if claims["aud"] != "https://issuer.example" || claims["iss"] != "client" || claims["nonce"] != "c-nonce" {
		t.Fatalf("claims = %v", claims)
	}

	token, err = KeyProof(context.Background(), key, KeyProofOptions{Audience: "https://issuer.example", KeyID: "did:key:z#z"})
	if err != nil {
		t.Fatal(err)
	}
	header, claims = verify(t, token, &key.private.PublicKey)
	if header["kid"] != "did:key:z#z" {
		t.Fatalf("kid = %v", header["kid"])
	}
	if _, found := header["jwk"]; found {
		t.Fatal("a kid-bound key proof must not carry a jwk header")
	}
	if _, found := claims["iss"]; found {
		t.Fatal("an empty Issuer must omit iss")
	}
}

func TestKeyProofRefusesUnlistedAlgorithm(t *testing.T) {
	key := newHSMKey(t, elliptic.P256())
	_, err := KeyProof(context.Background(), key, KeyProofOptions{Audience: "https://issuer.example", SigningAlgValues: []jose.SignatureAlgorithm{jose.ES384}})
	if !errors.Is(err, ErrProofAlgorithmNotSupported) {
		t.Fatalf("err = %v, want ErrProofAlgorithmNotSupported", err)
	}
	if key.signed != 0 {
		t.Fatal("nothing may be signed with an algorithm the issuer does not accept")
	}
}

func TestContextSignerReceivesTheOperationContext(t *testing.T) {
	key := &contextHSMKey{hsmKey: newHSMKey(t, elliptic.P256())}
	ctx := context.WithValue(context.Background(), ctxKey{}, "op")
	token, err := ClientAttestationPoP(ctx, key, ClientAttestationPoPOptions{ClientID: "client", Audience: "https://as.example", Challenge: "ch"})
	if err != nil {
		t.Fatal(err)
	}
	if key.seen != "op" {
		t.Fatalf("SignContext saw %v, want the caller's context", key.seen)
	}
	header, claims := verify(t, token, &key.private.PublicKey)
	if header["typ"] != TypeClientAttestationPoP || claims["challenge"] != "ch" || claims["aud"] != "https://as.example" || claims["iss"] != "client" {
		t.Fatalf("header = %v, claims = %v", header, claims)
	}
}

func TestCanceledContextSignsNothing(t *testing.T) {
	key := newHSMKey(t, elliptic.P256())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := DPoP(ctx, key, DPoPOptions{Method: "GET", URL: "https://rs.example/"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if key.signed != 0 {
		t.Fatal("a canceled operation must not reach the key")
	}
}

func TestAlgorithm(t *testing.T) {
	_, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaPrivate, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	mismatched := newHSMKey(t, elliptic.P256())
	mismatched.alg = "ES384"

	tests := []struct {
		name    string
		key     keystore.KeyEntry
		want    jose.SignatureAlgorithm
		wantErr bool
	}{
		{"P-256", newHSMKey(t, elliptic.P256()), jose.ES256, false},
		{"P-384", newHSMKey(t, elliptic.P384()), jose.ES384, false},
		{"P-521", newHSMKey(t, elliptic.P521()), jose.ES512, false},
		{"Ed25519", ed25519Key{private: edPrivate}, jose.EdDSA, false},
		{"RSA without alg", rsaKey{private: rsaPrivate}, "", true},
		{"RSA with alg", rsaKey{private: rsaPrivate, alg: "RS256"}, jose.RS256, false},
		{"alg the curve cannot produce", mismatched, "", true},
		{"nil key", nil, "", true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := Algorithm(test.key)
			if (err != nil) != test.wantErr || got != test.want {
				t.Fatalf("Algorithm = %q, %v; want %q, error %v", got, err, test.want, test.wantErr)
			}
		})
	}
}

func TestSignsWithEveryKeyKind(t *testing.T) {
	_, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaPrivate, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p521 := newHSMKey(t, elliptic.P521())
	jwkPrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwkEntry, err := keystore.NewKeyEntryFromJWK(jose.JSONWebKey{Key: jwkPrivate, KeyID: "jwk"})
	if err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		key    keystore.KeyEntry
		public any
	}{
		"Ed25519":  {ed25519Key{private: edPrivate}, edPrivate.Public()},
		"RS256":    {rsaKey{private: rsaPrivate, alg: "RS256"}, &rsaPrivate.PublicKey},
		"P-521":    {p521, &p521.private.PublicKey},
		"keystore": {jwkEntry, &jwkPrivate.PublicKey},
	} {
		t.Run(name, func(t *testing.T) {
			token, err := DPoP(context.Background(), test.key, DPoPOptions{Method: "GET", URL: "https://rs.example/r"})
			if err != nil {
				t.Fatal(err)
			}
			verify(t, token, test.public)
		})
	}
}

func TestClientAssertion(t *testing.T) {
	key := newHSMKey(t, elliptic.P256())
	key.kid = "registered"
	token, err := ClientAssertion(context.Background(), key, ClientAssertionOptions{ClientID: "client", Audience: "https://as.example"})
	if err != nil {
		t.Fatal(err)
	}
	header, claims := verify(t, token, &key.private.PublicKey)
	if header["kid"] != "registered" || header["typ"] != TypeClientAssertion {
		t.Fatalf("header = %v", header)
	}
	if claims["iss"] != "client" || claims["sub"] != "client" || claims["aud"] != "https://as.example" || claims["jti"] == "" {
		t.Fatalf("claims = %v", claims)
	}
	if _, err := ClientAssertion(context.Background(), key, ClientAssertionOptions{ClientID: "client", Audience: "https://as.example", Algorithm: jose.ES512}); err == nil {
		t.Fatal("an algorithm the key cannot produce must be refused")
	}
}

func TestStaticAttestations(t *testing.T) {
	attester := newHSMKey(t, elliptic.P256())
	attester.kid = "attester"
	certificate := selfSignedCertificate(t, attester.private)
	holderPrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	holder := jose.JSONWebKey{Key: holderPrivate, KeyID: "holder"}

	token, err := ClientAttestation(context.Background(), attester, ClientAttestationOptions{
		Issuer:    "https://attester.example",
		ClientID:  "client",
		ClientKey: holder,
		Audience:  "https://as.example",
		Chain:     []*x509.Certificate{certificate},
	})
	if err != nil {
		t.Fatal(err)
	}
	header, claims := verify(t, token, &attester.private.PublicKey)
	if header["typ"] != TypeClientAttestation || header["kid"] != "attester" {
		t.Fatalf("header = %v", header)
	}
	x5c, _ := header["x5c"].([]any)
	if len(x5c) != 1 || x5c[0] != base64.StdEncoding.EncodeToString(certificate.Raw) {
		t.Fatalf("x5c = %v", header["x5c"])
	}
	cnf, _ := claims["cnf"].(map[string]any)
	cnfJWK := requirePublicJWK(t, cnf["jwk"])
	if cnfJWK["kid"] != "holder" || claims["sub"] != "client" || claims["aud"] != "https://as.example" {
		t.Fatalf("claims = %v", claims)
	}

	token, err = KeyAttestation(context.Background(), attester, KeyAttestationOptions{
		Issuer:       "https://attester.example",
		AttestedKeys: []jose.JSONWebKey{holder},
		Nonce:        "c-nonce",
	})
	if err != nil {
		t.Fatal(err)
	}
	header, claims = verify(t, token, &attester.private.PublicKey)
	if header["typ"] != TypeKeyAttestation || claims["nonce"] != "c-nonce" {
		t.Fatalf("header = %v, claims = %v", header, claims)
	}
	attested, _ := claims["attested_keys"].([]any)
	if len(attested) != 1 {
		t.Fatalf("attested_keys = %v", claims["attested_keys"])
	}
	requirePublicJWK(t, attested[0])
}

func selfSignedCertificate(t *testing.T, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "attester"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}
