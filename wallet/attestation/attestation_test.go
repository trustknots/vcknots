package attestation

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	commonX509 "github.com/trustknots/vcknots/wallet/common/x509"
	"github.com/trustknots/vcknots/wallet/keystore"
)

func newPrivateJWK(t *testing.T, keyID string) jose.JSONWebKey {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return jose.JSONWebKey{Key: private, KeyID: keyID, Algorithm: "ES256", Use: "sig"}
}

func keyEntry(t *testing.T, jwk jose.JSONWebKey) keystore.KeyEntry {
	t.Helper()
	entry, err := keystore.NewKeyEntryFromJWK(jwk)
	require.NoError(t, err)
	return entry
}

// hsmKey is a KeyEntry that exposes only its public key and returns ASN.1 DER
// signatures, as a hardware module does.
type hsmKey struct{ private *ecdsa.PrivateKey }

func (k hsmKey) ID() string { return "hsm" }
func (k hsmKey) PublicKey() jose.JSONWebKey {
	return jose.JSONWebKey{Key: &k.private.PublicKey, KeyID: "hsm-attester"}
}
func (k hsmKey) Sign(data []byte) ([]byte, error) {
	digest := sha256.Sum256(data)
	return ecdsa.SignASN1(rand.Reader, k.private, digest[:])
}

// signJWT signs claims under typ with key, copying key.Certificates into x5c.
func signJWT(t *testing.T, key jose.JSONWebKey, typ string, claims map[string]any) string {
	t.Helper()
	options := (&jose.SignerOptions{}).WithType(jose.ContentType(typ))
	if len(key.Certificates) > 0 {
		x5c := make([]string, 0, len(key.Certificates))
		for _, certificate := range key.Certificates {
			x5c = append(x5c, base64.StdEncoding.EncodeToString(certificate.Raw))
		}
		options = options.WithHeader("x5c", x5c)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key.Key}, options)
	require.NoError(t, err)
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)
	return token
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	require.NoError(t, err)
	return encoded
}

// testLeafCertificate issues a certificate for key, self-signed or under a
// throwaway CA.
func testLeafCertificate(t *testing.T, key jose.JSONWebKey, selfSigned bool) *x509.Certificate {
	t.Helper()
	if !selfSigned {
		leaf, _ := testAttesterChain(t, key)
		return leaf
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public().Key, key.Key)
	require.NoError(t, err)
	certificate, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return certificate
}

// testAttesterChain issues a leaf for key under a fresh CA and returns both.
func testAttesterChain(t *testing.T, key jose.JSONWebKey) (leaf *x509.Certificate, anchor *x509.Certificate) {
	t.Helper()
	caKey := newPrivateJWK(t, "attester-ca-key")
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "attester CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		MaxPathLen:            -1,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public().Key, caKey.Key)
	require.NoError(t, err)
	anchor, err = x509.ParseCertificate(caDER)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano() + 1),
		Subject:               pkix.Name{CommonName: "attester"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		DNSNames:              []string{"attester.example"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, anchor, key.Public().Key, caKey.Key)
	require.NoError(t, err)
	leaf, err = x509.ParseCertificate(leafDER)
	require.NoError(t, err)
	return leaf, anchor
}

// noNetwork fails the test on any revocation fetch; the fixtures advertise no
// CRL distribution point.
type noNetwork struct{ t *testing.T }

func (transport noNetwork) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.t.Errorf("unexpected revocation request: %s", request.URL)
	return nil, errors.New("network must not be used by this fixture")
}

func anchoredPolicy(t *testing.T, anchors ...*x509.Certificate) TrustPolicy {
	t.Helper()
	return TrustPolicy{
		TrustAnchors:                anchors,
		AllowUnadvertisedRevocation: true,
		CRL:                         commonX509.CRLCheckerOptions{HTTPClient: &http.Client{Transport: noNetwork{t}}},
	}
}

func resolvedBy(key jose.JSONWebKey) TrustPolicy {
	return TrustPolicy{ResolveKey: func(JOSEHeader) (any, error) { return key.Public().Key, nil }}
}

func clientClaimsFor(clientKey jose.JSONWebKey) map[string]any {
	return map[string]any{
		"iss": "https://attester.example",
		"sub": "client-1",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Minute).Unix(),
		"cnf": map[string]any{"jwk": clientKey.Public()},
	}
}

func keyClaimsFor(holderKey jose.JSONWebKey, nonce string, expiry time.Time) map[string]any {
	return map[string]any{
		"iss":           "https://key-attester.example",
		"iat":           time.Now().Unix(),
		"exp":           expiry.Unix(),
		"nonce":         nonce,
		"attested_keys": []jose.JSONWebKey{holderKey.Public()},
	}
}

func with(base map[string]any, name string, value any) map[string]any {
	merged := map[string]any{}
	for key, v := range base {
		merged[key] = v
	}
	if value == nil {
		delete(merged, name)
	} else {
		merged[name] = value
	}
	return merged
}

func TestStaticClientAttesterProducesAValidAttestation(t *testing.T) {
	clientKey := newPrivateJWK(t, "client-key-1")
	attesterKey := newPrivateJWK(t, "attester-key-1")
	leaf := testLeafCertificate(t, attesterKey, false)
	attester := &StaticClientAttester{Key: keyEntry(t, attesterKey), Chain: []*x509.Certificate{leaf}, Issuer: "https://attester.example"}
	request := ClientRequest{ClientID: "client-1", ClientKey: clientKey, AuthorizationServer: "https://as.example"}

	attestation, err := attester.ClientAttestation(t.Context(), request)
	require.NoError(t, err)
	require.False(t, attestation.ExpiresAt.IsZero())

	// The x5c leaf authenticates it, and HAIP accepts the non-self-signed leaf.
	require.NoError(t, ValidateClientAttestation(t.Context(), attestation, request, TrustPolicy{}))
	require.NoError(t, ValidateClientAttestation(t.Context(), attestation, request, TrustPolicy{RequireX5C: true}))

	header, claims, err := parseJWT(attestation.JWT)
	require.NoError(t, err)
	require.Equal(t, clientAttestationType, header.Type)
	require.Len(t, header.X5C, 1)
	require.Equal(t, "https://attester.example", claims.Iss)
	require.Equal(t, "client-1", claims.Sub)
	// HAIP §4.4.1: the attestation names the server it was minted for.
	require.Equal(t, "https://as.example", claims.Aud)

	elsewhere := request
	elsewhere.AuthorizationServer = "https://other-as.example"
	require.ErrorContains(t, ValidateClientAttestation(t.Context(), attestation, elsewhere, TrustPolicy{}), "does not identify the authorization server")
}

// TestStaticAttestersSignWithAHardwareKey pins that an attester key need not
// expose private material.
func TestStaticAttestersSignWithAHardwareKey(t *testing.T) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key := hsmKey{private: private}
	public := key.PublicKey()
	clientKey := newPrivateJWK(t, "client-key-1")
	holderKey := newPrivateJWK(t, "holder-key-1")

	clientRequest := ClientRequest{ClientID: "client-1", ClientKey: clientKey}
	client, err := (&StaticClientAttester{Key: key, Issuer: "https://attester.example"}).ClientAttestation(t.Context(), clientRequest)
	require.NoError(t, err)
	require.NoError(t, ValidateClientAttestation(t.Context(), client, clientRequest, resolvedBy(public)))

	keyRequest := KeyRequest{Keys: []jose.JSONWebKey{holderKey.Public()}, Nonce: "cnonce-1"}
	attested, err := (&StaticKeyAttester{Key: key, Issuer: "https://key-attester.example"}).KeyAttestation(t.Context(), keyRequest)
	require.NoError(t, err)
	require.NoError(t, ValidateKeyAttestation(t.Context(), attested, keyRequest, resolvedBy(public)))
}

func TestStaticAttestersRefuseMissingInput(t *testing.T) {
	attesterKey := keyEntry(t, newPrivateJWK(t, "attester-key-1"))
	clientKey := newPrivateJWK(t, "client-key-1")

	_, err := (&StaticClientAttester{Issuer: "https://attester.example"}).ClientAttestation(t.Context(), ClientRequest{ClientID: "client-1", ClientKey: clientKey})
	require.ErrorContains(t, err, "key is required")
	_, err = (&StaticClientAttester{Key: attesterKey}).ClientAttestation(t.Context(), ClientRequest{ClientID: "client-1", ClientKey: clientKey})
	require.ErrorContains(t, err, "issuer")
	_, err = (&StaticClientAttester{Key: attesterKey, Issuer: "https://attester.example"}).ClientAttestation(t.Context(), ClientRequest{ClientKey: clientKey})
	require.ErrorContains(t, err, "client_id")
	_, err = (&StaticKeyAttester{Key: attesterKey, Issuer: "https://key-attester.example"}).KeyAttestation(t.Context(), KeyRequest{})
	require.ErrorContains(t, err, "at least one")
	_, err = (&StaticKeyAttester{Key: attesterKey, Issuer: "https://key-attester.example"}).KeyAttestation(t.Context(), KeyRequest{Keys: []jose.JSONWebKey{{}}})
	require.ErrorContains(t, err, "index 0")
}

func TestClientAttestationClaimsAreChecked(t *testing.T) {
	clientKey := newPrivateJWK(t, "client-key-1")
	otherKey := newPrivateJWK(t, "other-client-key-1")
	attesterKey := newPrivateJWK(t, "attester-key-1")
	request := ClientRequest{ClientID: "client-1", ClientKey: clientKey, AuthorizationServer: "https://as.example"}
	claims := clientClaimsFor(clientKey)

	cases := map[string]struct {
		typ     string
		claims  map[string]any
		wantErr string
	}{
		"wrong typ":             {"JWT", claims, "typ must be"},
		"wrong sub":             {clientAttestationType, with(claims, "sub", "someone-else"), "does not match client_id"},
		"other cnf key":         {clientAttestationType, clientClaimsFor(otherKey), "cnf.jwk does not match"},
		"missing cnf":           {clientAttestationType, with(claims, "cnf", nil), "missing cnf.jwk"},
		"expired":               {clientAttestationType, with(claims, "exp", time.Now().Add(-time.Minute).Unix()), "expired"},
		"missing exp":           {clientAttestationType, with(claims, "exp", nil), "missing exp"},
		"foreign aud":           {clientAttestationType, with(claims, "aud", "https://other-as.example"), "does not identify the authorization server"},
		"foreign aud array":     {clientAttestationType, with(claims, "aud", []string{"https://other-as.example"}), "does not identify the authorization server"},
		"non-string aud member": {clientAttestationType, with(claims, "aud", 7), "does not identify the authorization server"},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			token := signJWT(t, attesterKey, testCase.typ, testCase.claims)
			err := ValidateClientAttestation(t.Context(), &ClientAttestation{JWT: token}, request, resolvedBy(attesterKey))
			require.ErrorIs(t, err, ErrClientAttestationInvalid)
			require.ErrorContains(t, err, testCase.wantErr)
		})
	}

	for name, aud := range map[string]any{"string": "https://as.example", "array": []string{"https://other-as.example", "https://as.example"}, "absent": nil} {
		t.Run("aud "+name+" is accepted", func(t *testing.T) {
			token := signJWT(t, attesterKey, clientAttestationType, with(claims, "aud", aud))
			require.NoError(t, ValidateClientAttestation(t.Context(), &ClientAttestation{JWT: token}, request, resolvedBy(attesterKey)))
		})
	}

	t.Run("the provider's ExpiresAt ends use before exp", func(t *testing.T) {
		token := signJWT(t, attesterKey, clientAttestationType, claims)
		early := &ClientAttestation{JWT: token, ExpiresAt: time.Now().Add(-time.Second)}
		require.ErrorContains(t, ValidateClientAttestation(t.Context(), early, request, resolvedBy(attesterKey)), "expired")
	})
}

func TestRequireX5CRefusesAMissingOrSelfSignedChain(t *testing.T) {
	clientKey := newPrivateJWK(t, "client-key-1")
	holderKey := newPrivateJWK(t, "holder-key-1")
	attesterKey := newPrivateJWK(t, "attester-key-1")
	selfSignedKey := newPrivateJWK(t, "self-signed-attester")
	selfSignedKey.Certificates = []*x509.Certificate{testLeafCertificate(t, selfSignedKey, true)}
	clientRequest := ClientRequest{ClientID: "client-1", ClientKey: clientKey}
	keyRequest := KeyRequest{Keys: []jose.JSONWebKey{holderKey}, Nonce: "cnonce-1"}
	policy := resolvedBy(attesterKey)
	policy.RequireX5C = true

	withoutX5C := signJWT(t, attesterKey, clientAttestationType, clientClaimsFor(clientKey))
	require.ErrorContains(t, ValidateClientAttestation(t.Context(), &ClientAttestation{JWT: withoutX5C}, clientRequest, policy), "x5c")
	selfSigned := signJWT(t, selfSignedKey, clientAttestationType, clientClaimsFor(clientKey))
	require.ErrorContains(t, ValidateClientAttestation(t.Context(), &ClientAttestation{JWT: selfSigned}, clientRequest, policy), "self-signed")

	keyWithoutX5C := signJWT(t, attesterKey, keyAttestationType, keyClaimsFor(holderKey, "cnonce-1", time.Now().Add(time.Minute)))
	require.ErrorContains(t, ValidateKeyAttestation(t.Context(), &KeyAttestation{JWT: keyWithoutX5C}, keyRequest, policy), "x5c")
	keySelfSigned := signJWT(t, selfSignedKey, keyAttestationType, keyClaimsFor(holderKey, "cnonce-1", time.Now().Add(time.Minute)))
	require.ErrorContains(t, ValidateKeyAttestation(t.Context(), &KeyAttestation{JWT: keySelfSigned}, keyRequest, policy), "self-signed")
}

func TestStaticKeyAttesterProducesAValidAttestation(t *testing.T) {
	holderKey := newPrivateJWK(t, "holder-key-1")
	attesterKey := newPrivateJWK(t, "key-attester-1")
	attester := &StaticKeyAttester{Key: keyEntry(t, attesterKey), Issuer: "https://key-attester.example"}
	request := KeyRequest{Keys: []jose.JSONWebKey{holderKey}, Nonce: "cnonce-1", Audience: "https://issuer.example"}

	attestation, err := attester.KeyAttestation(t.Context(), request)
	require.NoError(t, err)
	require.NoError(t, ValidateKeyAttestation(t.Context(), attestation, request, resolvedBy(attesterKey)))

	header, claims, err := parseJWT(attestation.JWT)
	require.NoError(t, err)
	require.Equal(t, keyAttestationType, header.Type)
	require.Equal(t, "cnonce-1", claims.Nonce)
	require.Len(t, claims.AttestedKeys, 1)
}

func TestKeyAttestationClaimsAreChecked(t *testing.T) {
	holderKey := newPrivateJWK(t, "holder-key-1")
	otherKey := newPrivateJWK(t, "other-holder-key-1")
	attesterKey := newPrivateJWK(t, "key-attester-1")
	request := KeyRequest{Keys: []jose.JSONWebKey{holderKey}, Nonce: "cnonce-1", Audience: "https://issuer.example"}
	valid := keyClaimsFor(holderKey, "cnonce-1", time.Now().Add(time.Minute))

	cases := map[string]struct {
		typ     string
		claims  map[string]any
		wantErr string
	}{
		"another holder key": {keyAttestationType, keyClaimsFor(otherKey, "cnonce-1", time.Now().Add(time.Minute)), "does not attest the holder key"},
		"a stale nonce":      {keyAttestationType, keyClaimsFor(holderKey, "stale", time.Now().Add(time.Minute)), "nonce"},
		"expired":            {keyAttestationType, keyClaimsFor(holderKey, "cnonce-1", time.Now().Add(-time.Minute)), "expired"},
		"missing exp":        {keyAttestationType, with(valid, "exp", nil), "missing exp"},
		"wrong typ":          {"JWT", valid, "typ must be"},
		"foreign aud":        {keyAttestationType, with(valid, "aud", "https://other-issuer.example"), "does not identify the credential issuer"},
		"invalid attested":   {keyAttestationType, with(valid, "attested_keys", []any{map[string]any{"kty": "EC"}}), "malformed"},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			token := signJWT(t, attesterKey, testCase.typ, testCase.claims)
			err := ValidateKeyAttestation(t.Context(), &KeyAttestation{JWT: token}, request, resolvedBy(attesterKey))
			require.ErrorIs(t, err, ErrKeyAttestationInvalid)
			require.ErrorContains(t, err, testCase.wantErr)
		})
	}

	t.Run("an absent aud is accepted", func(t *testing.T) {
		token := signJWT(t, attesterKey, keyAttestationType, valid)
		require.NoError(t, ValidateKeyAttestation(t.Context(), &KeyAttestation{JWT: token}, request, resolvedBy(attesterKey)))
	})
}

// TestValidateAuthenticatesTheAttester pins that the signer is established
// before any claim is believed: the x5c leaf when present, ResolveKey
// otherwise, and neither means refusal.
func TestValidateAuthenticatesTheAttester(t *testing.T) {
	clientKey := newPrivateJWK(t, "client-key-1")
	attesterKey := newPrivateJWK(t, "attester-key-1")
	leaf, _ := testAttesterChain(t, attesterKey)
	request := ClientRequest{ClientID: "client-1", ClientKey: clientKey, AuthorizationServer: "https://as.example"}
	attest := func(key jose.JSONWebKey, chain ...*x509.Certificate) *ClientAttestation {
		attestation, err := (&StaticClientAttester{Key: keyEntry(t, key), Chain: chain, Issuer: "https://attester.example"}).ClientAttestation(t.Context(), request)
		require.NoError(t, err)
		return attestation
	}

	t.Run("the x5c leaf key verifies the signature", func(t *testing.T) {
		require.NoError(t, ValidateClientAttestation(t.Context(), attest(attesterKey, leaf), request, TrustPolicy{}))
	})

	t.Run("a resolver verifies an attestation without x5c", func(t *testing.T) {
		require.NoError(t, ValidateClientAttestation(t.Context(), attest(attesterKey), request, resolvedBy(attesterKey)))
	})

	t.Run("an attestation with neither is refused", func(t *testing.T) {
		err := ValidateClientAttestation(t.Context(), attest(attesterKey), request, TrustPolicy{})
		require.ErrorContains(t, err, "no x5c chain")
	})

	t.Run("a resolver error refuses the attestation", func(t *testing.T) {
		policy := TrustPolicy{ResolveKey: func(JOSEHeader) (any, error) { return nil, errors.New("unknown kid") }}
		require.ErrorContains(t, ValidateClientAttestation(t.Context(), attest(attesterKey), request, policy), "unknown kid")
		policy.ResolveKey = func(JOSEHeader) (any, error) { return nil, nil }
		require.ErrorContains(t, ValidateClientAttestation(t.Context(), attest(attesterKey), request, policy), "returned no key")
	})

	t.Run("the resolver sees the header", func(t *testing.T) {
		var seen JOSEHeader
		policy := TrustPolicy{ResolveKey: func(header JOSEHeader) (any, error) {
			seen = header
			return attesterKey.Public().Key, nil
		}}
		require.NoError(t, ValidateClientAttestation(t.Context(), attest(attesterKey), request, policy))
		require.Equal(t, JOSEHeader{Type: clientAttestationType, Algorithm: "ES256", KeyID: "attester-key-1"}, seen)
	})

	t.Run("a signature by another key under the genuine certificate is refused", func(t *testing.T) {
		impostor := attest(newPrivateJWK(t, "impostor-key"))
		parts := strings.Split(impostor.JWT, ".")
		forged := &ClientAttestation{JWT: strings.Join([]string{
			base64.RawURLEncoding.EncodeToString(mustJSON(t, map[string]any{
				"typ": clientAttestationType,
				"alg": "ES256",
				"x5c": []string{base64.StdEncoding.EncodeToString(leaf.Raw)},
			})), parts[1], parts[2],
		}, ".")}
		require.ErrorContains(t, ValidateClientAttestation(t.Context(), forged, request, TrustPolicy{}), "signature could not be verified")
	})

	// ResolveKey applies only to attestations without x5c, so a caller need
	// not inspect the header to decide whether to configure it.
	t.Run("a resolver does not override the x5c leaf", func(t *testing.T) {
		otherKey := newPrivateJWK(t, "other-key")
		calls := 0
		policy := TrustPolicy{ResolveKey: func(JOSEHeader) (any, error) {
			calls++
			return otherKey.Public().Key, nil
		}}
		require.NoError(t, ValidateClientAttestation(t.Context(), attest(attesterKey, leaf), request, policy))
		require.Zero(t, calls)

		// The leaf still decides: an attestation signed by another key under
		// the genuine leaf fails even though the resolver would vouch for it.
		impostorKey := newPrivateJWK(t, "impostor")
		impostor := attest(impostorKey, leaf)
		policy.ResolveKey = func(JOSEHeader) (any, error) { return impostorKey.Public().Key, nil }
		require.ErrorContains(t, ValidateClientAttestation(t.Context(), impostor, request, policy), "signature could not be verified")
	})

	t.Run("a tampered payload is refused", func(t *testing.T) {
		parts := strings.Split(attest(attesterKey, leaf).JWT, ".")
		tampered := &ClientAttestation{JWT: strings.Join([]string{
			parts[0], base64.RawURLEncoding.EncodeToString(mustJSON(t, with(clientClaimsFor(clientKey), "iss", "https://evil.example"))), parts[2],
		}, ".")}
		require.ErrorContains(t, ValidateClientAttestation(t.Context(), tampered, request, TrustPolicy{}), "signature could not be verified")
	})

	t.Run("a MAC is refused", func(t *testing.T) {
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte("0123456789abcdef0123456789abcdef")}, (&jose.SignerOptions{}).WithType(clientAttestationType))
		require.NoError(t, err)
		token, err := jwt.Signed(signer).Claims(clientClaimsFor(clientKey)).Serialize()
		require.NoError(t, err)
		policy := TrustPolicy{ResolveKey: func(JOSEHeader) (any, error) { return []byte("0123456789abcdef0123456789abcdef"), nil }}
		require.ErrorContains(t, ValidateClientAttestation(t.Context(), &ClientAttestation{JWT: token}, request, policy), "not a verifiable JWS")
	})
}

func TestValidateChecksTheChain(t *testing.T) {
	clientKey := newPrivateJWK(t, "client-key-1")
	holderKey := newPrivateJWK(t, "holder-key-1")
	attesterKey := newPrivateJWK(t, "attester-key-1")
	leaf, anchor := testAttesterChain(t, attesterKey)
	clientRequest := ClientRequest{ClientID: "client-1", ClientKey: clientKey, AuthorizationServer: "https://as.example"}
	keyRequest := KeyRequest{Keys: []jose.JSONWebKey{holderKey}, Nonce: "cnonce-1", Audience: "https://issuer.example"}
	client, err := (&StaticClientAttester{Key: keyEntry(t, attesterKey), Chain: []*x509.Certificate{leaf}, Issuer: "https://attester.example"}).ClientAttestation(t.Context(), clientRequest)
	require.NoError(t, err)
	key, err := (&StaticKeyAttester{Key: keyEntry(t, attesterKey), Chain: []*x509.Certificate{leaf}, Issuer: "https://key-attester.example"}).KeyAttestation(t.Context(), keyRequest)
	require.NoError(t, err)

	t.Run("a chain reaching the anchor is trusted", func(t *testing.T) {
		policy := anchoredPolicy(t, anchor)
		policy.RequireX5C = true
		require.NoError(t, ValidateClientAttestation(t.Context(), client, clientRequest, policy))
		require.NoError(t, ValidateKeyAttestation(t.Context(), key, keyRequest, policy))
	})

	t.Run("a chain reaching no anchor is refused", func(t *testing.T) {
		_, unrelated := testAttesterChain(t, newPrivateJWK(t, "unrelated-attester"))
		require.ErrorContains(t, ValidateClientAttestation(t.Context(), client, clientRequest, anchoredPolicy(t, unrelated)), "chain is not trusted")
	})

	t.Run("anchors without a revocation client are refused", func(t *testing.T) {
		err := ValidateClientAttestation(t.Context(), client, clientRequest, TrustPolicy{TrustAnchors: []*x509.Certificate{anchor}})
		require.ErrorContains(t, err, "no CRL HTTP client")
	})

	t.Run("HAIP refuses the trust anchor inside x5c", func(t *testing.T) {
		carried, err := (&StaticKeyAttester{Key: keyEntry(t, attesterKey), Chain: []*x509.Certificate{leaf, anchor}, Issuer: "https://key-attester.example"}).KeyAttestation(t.Context(), keyRequest)
		require.NoError(t, err)
		policy := anchoredPolicy(t, anchor)
		policy.RequireX5C = true
		require.ErrorContains(t, ValidateKeyAttestation(t.Context(), carried, keyRequest, policy), "trust anchor")
	})
}

func TestValidateWrapsTheSentinels(t *testing.T) {
	clientRequest := ClientRequest{ClientID: "client-1", ClientKey: newPrivateJWK(t, "client-key-1")}
	keyRequest := KeyRequest{Keys: []jose.JSONWebKey{newPrivateJWK(t, "holder-key-1")}}

	require.ErrorIs(t, ValidateClientAttestation(t.Context(), nil, clientRequest, TrustPolicy{}), ErrClientAttestationInvalid)
	require.ErrorIs(t, ValidateClientAttestation(t.Context(), &ClientAttestation{JWT: "not-a-jwt"}, clientRequest, TrustPolicy{}), ErrClientAttestationInvalid)
	require.ErrorIs(t, ValidateKeyAttestation(t.Context(), nil, keyRequest, TrustPolicy{}), ErrKeyAttestationInvalid)
	require.ErrorIs(t, ValidateKeyAttestation(t.Context(), &KeyAttestation{JWT: "a.b.c"}, keyRequest, TrustPolicy{}), ErrKeyAttestationInvalid)
}

// TestKeyRequestIsJSON pins the wire shape a remote provider receives.
func TestKeyRequestIsJSON(t *testing.T) {
	holderPrivate := newPrivateJWK(t, "holder-key-1")
	holder := holderPrivate.Public()
	encoded := mustJSON(t, KeyRequest{Keys: []jose.JSONWebKey{holder}, Nonce: "n", Audience: "https://issuer.example"})
	var decoded KeyRequest
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	require.Equal(t, "n", decoded.Nonce)
	require.Equal(t, "https://issuer.example", decoded.Audience)
	want, err := holder.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	got, err := decoded.Keys[0].Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, want, got)
}
