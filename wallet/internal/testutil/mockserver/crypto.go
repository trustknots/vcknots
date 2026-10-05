package mockserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net/url"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// KeyPair represents a cryptographic key pair for testing
type KeyPair struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
	KeyID      string

	chainOnce sync.Once
	chain     []string
}

// credentialCA is the test certification authority that certifies every
// KeyPair's credential signing key, so a wallet test can authenticate a
// mock issuer's credentials through their x5c chain (SD-JWT VC -19 §2.5).
var credentialCA = sync.OnceValues(func() (*x509.Certificate, *ecdsa.PrivateKey) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Mock Credential Issuer CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(7 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return certificate, key
})

// CredentialTrustAnchors returns the anchor that certifies the credential
// signing keys of every KeyPair (see CertificateChain).
func CredentialTrustAnchors() []*x509.Certificate {
	certificate, _ := credentialCA()
	return []*x509.Certificate{certificate}
}

// CertificateChain returns the x5c header value (the leaf only) of a
// certificate for kp's public key, issued by the CredentialTrustAnchors CA.
// The leaf names the loopback host the mock servers run on (localhost and
// the URI http://127.0.0.1), so a credential whose iss is a mock server URL
// binds to it under IssuerX509TrustOptions.Experimental.AllowHTTP.
func (kp *KeyPair) CertificateChain() []string {
	kp.chainOnce.Do(func() {
		caCertificate, caKey := credentialCA()
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
		if err != nil {
			panic(err)
		}
		template := &x509.Certificate{
			SerialNumber:          serial,
			Subject:               pkix.Name{CommonName: "Mock Credential Issuer " + kp.KeyID},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(7 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
			DNSNames:              []string{"localhost"},
			URIs:                  []*url.URL{{Scheme: "http", Host: "127.0.0.1"}},
		}
		der, err := x509.CreateCertificate(rand.Reader, template, caCertificate, kp.PublicKey, caKey)
		if err != nil {
			panic(err)
		}
		kp.chain = []string{base64.StdEncoding.EncodeToString(der)}
	})
	return kp.chain
}

// GenerateKeyPair creates a new ECDSA P-256 key pair for testing
func GenerateKeyPair(keyID string) (*KeyPair, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		KeyID:      keyID,
	}, nil
}

// MustGenerateKeyPair is like GenerateKeyPair but panics on error
func MustGenerateKeyPair(keyID string) *KeyPair {
	kp, err := GenerateKeyPair(keyID)
	if err != nil {
		panic(err)
	}
	return kp
}

// CreateJWK creates a JOSE JSONWebKey from the key pair
func (kp *KeyPair) CreateJWK() jose.JSONWebKey {
	return jose.JSONWebKey{
		Key:       kp.PrivateKey,
		KeyID:     kp.KeyID,
		Algorithm: string(jose.ES256),
	}
}

// CreatePublicJWK creates a public JOSE JSONWebKey from the key pair
func (kp *KeyPair) CreatePublicJWK() jose.JSONWebKey {
	return jose.JSONWebKey{
		Key:       kp.PublicKey,
		KeyID:     kp.KeyID,
		Algorithm: string(jose.ES256),
	}
}

// CreateJWKS creates a JWKS (JSON Web Key Set) containing this key
func (kp *KeyPair) CreateJWKS() map[string]interface{} {
	publicJWK := kp.CreatePublicJWK()
	return map[string]interface{}{
		"keys": []jose.JSONWebKey{publicJWK},
	}
}

// JWTBuilder helps create signed JWTs for testing
type JWTBuilder struct {
	keyPair *KeyPair
	signer  jose.Signer
}

// NewJWTBuilder creates a new JWT builder with the given key pair
func NewJWTBuilder(keyPair *KeyPair) (*JWTBuilder, error) {
	joseKey := keyPair.CreateJWK()

	// Create signer with proper 'typ' header for OID4VP JWT Request Objects
	signerOptions := &jose.SignerOptions{}
	signerOptions.WithType("oauth-authz-req+jwt") // Required by OID4VP specification

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: joseKey}, signerOptions)
	if err != nil {
		return nil, err
	}

	return &JWTBuilder{
		keyPair: keyPair,
		signer:  signer,
	}, nil
}

// MustNewJWTBuilder is like NewJWTBuilder but panics on error
func MustNewJWTBuilder(keyPair *KeyPair) *JWTBuilder {
	builder, err := NewJWTBuilder(keyPair)
	if err != nil {
		panic(err)
	}
	return builder
}

// CreateSignedJWT creates a signed JWT with the given issuer and claims
func (jb *JWTBuilder) CreateSignedJWT(issuer string, claims map[string]interface{}) (string, error) {
	now := time.Now()
	defaultClaims := map[string]interface{}{
		"iss": issuer,
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}

	// Merge with provided claims (provided claims override defaults)
	for k, v := range claims {
		defaultClaims[k] = v
	}

	token, err := jwt.Signed(jb.signer).Claims(defaultClaims).Serialize()
	return token, err
}

// CreateSignedCredentialJWT creates a credential JWT with the given issuer and
// claims whose protected header carries the key pair's certificate chain as
// x5c, so its issuer can be authenticated with CredentialTrustAnchors.
func (jb *JWTBuilder) CreateSignedCredentialJWT(issuer string, claims map[string]interface{}) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jb.keyPair.CreateJWK()},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("x5c", jb.keyPair.CertificateChain()))
	if err != nil {
		return "", err
	}
	now := time.Now()
	defaultClaims := map[string]interface{}{
		"iss": issuer,
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}
	for k, v := range claims {
		defaultClaims[k] = v
	}
	return jwt.Signed(signer).Claims(defaultClaims).Serialize()
}

// CreateSignedJWTWithDuration creates a signed JWT with custom expiration duration
func (jb *JWTBuilder) CreateSignedJWTWithDuration(issuer string, claims map[string]interface{}, duration time.Duration) (string, error) {
	now := time.Now()
	defaultClaims := map[string]interface{}{
		"iss": issuer,
		"iat": now.Unix(),
		"exp": now.Add(duration).Unix(),
	}

	for k, v := range claims {
		defaultClaims[k] = v
	}

	token, err := jwt.Signed(jb.signer).Claims(defaultClaims).Serialize()
	return token, err
}
