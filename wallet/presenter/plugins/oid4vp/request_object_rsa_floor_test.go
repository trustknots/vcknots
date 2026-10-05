package oid4vp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"

	commonJOSE "github.com/trustknots/vcknots/wallet/common/jose"
)

// rsaSignedRequestObject issues an RSA leaf of the given size under the
// fixture's trust anchor and signs the fixture claims with RS256, bound to it
// through x509_hash.
func rsaSignedRequestObject(t *testing.T, f *requestObjectFixture, bits int) (clientID, requestObject string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "RSA verifier"},
		NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		CRLDistributionPoints: []string{f.server.URL + "/root.crl"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, f.root, &key.PublicKey, f.rootKey)
	require.NoError(t, err)
	hash := sha256.Sum256(der)
	clientID = "x509_hash:" + base64.RawURLEncoding.EncodeToString(hash[:])
	claims := f.claims()
	claims["client_id"] = clientID
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("oauth-authz-req+jwt").WithHeader("x5c", []string{base64.StdEncoding.EncodeToString(der)}))
	require.NoError(t, err)
	requestObject, err = jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)
	return clientID, requestObject
}

// RFC 7518 Section 3.3: "A key of size 2048 bits or larger MUST be used
// with these algorithms". A Request Object signed under a 1024-bit RSA
// certificate is refused before its signature is checked; a 2048-bit one is
// admitted.
func TestRequestObjectRefusesAnRSAVerifierKeyBelow2048Bits(t *testing.T) {
	f := newRequestObjectFixture(t)
	clientID, weak := rsaSignedRequestObject(t, f, 1024)
	_, err := parseRequestObjectForTest(f.presenter(), weak, clientID)
	require.ErrorIs(t, err, commonJOSE.ErrVerificationKeyTooWeak)

	clientID, strong := rsaSignedRequestObject(t, f, 2048)
	_, err = parseRequestObjectForTest(f.presenter(), strong, clientID)
	require.NoError(t, err)
}
