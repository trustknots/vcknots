package acceptance

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/internal/testutil"
	"github.com/trustknots/vcknots/wallet/profile"
	"github.com/trustknots/vcknots/wallet/serializer"
	"github.com/trustknots/vcknots/wallet/verifier"
)

// newTestAcceptor builds an Acceptor with the default serialization and
// verification plugins.
func newTestAcceptor(t *testing.T, p profile.Profile) *Acceptor {
	t.Helper()
	serialization, err := serializer.NewSerializationDispatcher(serializer.WithDefaultConfig())
	require.NoError(t, err)
	verification, err := verifier.NewVerificationDispatcher(verifier.WithDefaultConfig())
	require.NoError(t, err)
	acceptor, err := NewAcceptor(p, serialization, verification)
	require.NoError(t, err)
	return acceptor
}

// sdJWT is the Options for an SD-JWT VC bound to holder.
func sdJWT(holder *jose.JSONWebKey) Options {
	return Options{Flavor: credential.SDJwtVC, HolderKey: holder}
}

// newHolderKey returns a fresh public holder JWK.
func newHolderKey(t *testing.T) jose.JSONWebKey {
	t.Helper()
	return jose.JSONWebKey{Key: &testutil.NewP256Key(t).PublicKey, KeyID: "holder", Algorithm: "ES256", Use: "sig"}
}

type testWire struct {
	issuer string
	vct    string
	typ    string
	cnf    *jose.JSONWebKey
	// cnfRaw sets the confirmation object verbatim and wins over cnf.
	cnfRaw          map[string]any
	exp             time.Time
	nbf             *time.Time
	disclosures     map[string]string
	extraDisclosure bool
	sdAlg           string
	x5c             []string
	// signingKey is the ES256 issuer key; alg and signer replace it for
	// another algorithm or key type.
	signingKey      *ecdsa.PrivateKey
	alg             jose.SignatureAlgorithm
	signer          any
	kid             string
	tamperSignature bool
}

func buildWire(t *testing.T, spec testWire) string {
	t.Helper()
	if spec.typ == "" {
		spec.typ = "dc+sd-jwt"
	}
	if spec.issuer == "" {
		spec.issuer = "https://issuer.example.test"
	}
	if spec.vct == "" {
		spec.vct = "urn:test:acceptance"
	}
	if spec.exp.IsZero() {
		spec.exp = time.Now().Add(time.Hour)
	}
	if spec.alg == "" {
		spec.alg = jose.ES256
	}
	if spec.signer == nil {
		require.NotNil(t, spec.signingKey)
		spec.signer = spec.signingKey
	}

	claims := map[string]any{
		"iss": spec.issuer,
		"vct": spec.vct,
		"iat": time.Now().Unix(),
		"exp": spec.exp.Unix(),
	}
	if spec.nbf != nil {
		claims["nbf"] = spec.nbf.Unix()
	}
	switch {
	case spec.cnfRaw != nil:
		claims["cnf"] = spec.cnfRaw
	case spec.cnf != nil:
		claims["cnf"] = map[string]any{"jwk": spec.cnf.Public()}
	}

	var disclosures, hashes []string
	names := make([]string, 0, len(spec.disclosures))
	for name := range spec.disclosures {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		raw, err := json.Marshal([]any{"salt-" + name, name, spec.disclosures[name]})
		require.NoError(t, err)
		encoded := base64.RawURLEncoding.EncodeToString(raw)
		disclosures = append(disclosures, encoded)
		digest := sha256.Sum256([]byte(encoded))
		hashes = append(hashes, base64.RawURLEncoding.EncodeToString(digest[:]))
	}
	if len(hashes) > 0 {
		claims["_sd"] = hashes
		claims["_sd_alg"] = "sha-256"
		if spec.sdAlg != "" {
			claims["_sd_alg"] = spec.sdAlg
		}
	}
	if spec.extraDisclosure {
		raw, err := json.Marshal([]any{"orphan-salt", "orphan_claim", "orphan-value"})
		require.NoError(t, err)
		disclosures = append(disclosures, base64.RawURLEncoding.EncodeToString(raw))
	}

	signerOptions := (&jose.SignerOptions{}).WithType(jose.ContentType(spec.typ))
	if len(spec.x5c) > 0 {
		signerOptions = signerOptions.WithHeader("x5c", spec.x5c)
	}
	if spec.kid != "" {
		signerOptions = signerOptions.WithHeader("kid", spec.kid)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: spec.alg, Key: spec.signer}, signerOptions)
	require.NoError(t, err)
	signed, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)
	wire := strings.Join(append([]string{signed}, disclosures...), "~") + "~"
	if spec.tamperSignature {
		wire = tamperIssuerSignature(t, wire)
	}
	return wire
}

func tamperIssuerSignature(t *testing.T, wire string) string {
	t.Helper()
	parts := strings.SplitN(wire, "~", 2)
	jwtParts := strings.Split(parts[0], ".")
	require.Len(t, jwtParts, 3)
	signature, err := base64.RawURLEncoding.DecodeString(jwtParts[2])
	require.NoError(t, err)
	signature[0] ^= 0xFF
	jwtParts[2] = base64.RawURLEncoding.EncodeToString(signature)
	return strings.Join(jwtParts, ".") + "~" + parts[1]
}

// unsignedWire is an SD-JWT VC whose header names algorithm and whose
// signature is meaningless, for "none" and MAC algorithms no signer produces.
func unsignedWire(t *testing.T, algorithm string) string {
	t.Helper()
	header, err := json.Marshal(map[string]any{"alg": algorithm, "typ": "dc+sd-jwt"})
	require.NoError(t, err)
	claims, err := json.Marshal(map[string]any{
		"iss": "https://issuer.example.test",
		"vct": "urn:test:acceptance",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	require.NoError(t, err)
	return strings.Join([]string{
		base64.RawURLEncoding.EncodeToString(header),
		base64.RawURLEncoding.EncodeToString(claims),
		base64.RawURLEncoding.EncodeToString([]byte("not-a-signature")),
	}, ".") + "~"
}

type testIssuerChain struct {
	caCert   *x509.Certificate
	caKey    *ecdsa.PrivateKey
	leafCert *x509.Certificate
	leafKey  *ecdsa.PrivateKey
}

func (c testIssuerChain) x5c() []string {
	return []string{
		base64.StdEncoding.EncodeToString(c.leafCert.Raw),
		base64.StdEncoding.EncodeToString(c.caCert.Raw),
	}
}

// leafOnlyX5C is the chain HAIP §6.1.1 asks for: no trust anchor.
func (c testIssuerChain) leafOnlyX5C() []string {
	return []string{base64.StdEncoding.EncodeToString(c.leafCert.Raw)}
}

func (c testIssuerChain) anchors() []*x509.Certificate {
	return []*x509.Certificate{c.caCert}
}

func newTestIssuerChain(t *testing.T, dnsNames []string) testIssuerChain {
	t.Helper()
	caKey := testutil.NewP256Key(t)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Acceptance Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leafKey := testutil.NewP256Key(t)
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Acceptance Test Issuer"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)
	return testIssuerChain{caCert: caCert, caKey: caKey, leafCert: leafCert, leafKey: leafKey}
}

// resolving is a Policy whose resolver returns keys.
func resolving(keys ...jose.JSONWebKey) Policy {
	return Policy{ResolveIssuerKeys: func(string, map[string]any) ([]jose.JSONWebKey, error) {
		return keys, nil
	}}
}

// x509Trust is a Policy trusting anchors, with no CRL distribution points
// required.
func x509Trust(anchors []*x509.Certificate, dnsBinding bool) Policy {
	return Policy{IssuerX509: &IssuerX509TrustOptions{
		TrustAnchors:                anchors,
		AllowUnadvertisedRevocation: true,
		RequireIssuerDNSBinding:     dnsBinding,
	}}
}

func ptr[T any](value T) *T {
	return &value
}
