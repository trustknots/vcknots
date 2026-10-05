package oid4vci

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	commonjose "github.com/trustknots/vcknots/wallet/common/jose"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

// TestFetchIssuerMetadataRefusesAnRSASignerBelow2048Bits covers RFC 7518
// Section 3.3: "A key of size 2048 bits or larger MUST be used with these
// algorithms". Signed Credential Issuer Metadata whose leaf certificate
// carries a shorter RSA key is not verified, even though the chain reaches the
// configured anchor.
func TestFetchIssuerMetadataRefusesAnRSASignerBelow2048Bits(t *testing.T) {
	for _, test := range []struct {
		bits    int
		wantErr bool
	}{
		{bits: 1024, wantErr: true},
		{bits: 2048, wantErr: false},
	} {
		fixture := newSignedMetadataFixture(t)
		leafKey, err := rsa.GenerateKey(rand.Reader, test.bits)
		if err != nil {
			t.Fatal(err)
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
			SerialNumber:          big.NewInt(3),
			Subject:               pkix.Name{CommonName: "RSA Signed Metadata Issuer"},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
		}, fixture.caCert, &leafKey.PublicKey, fixture.caKey)
		if err != nil {
			t.Fatal(err)
		}
		serverURL, client, _ := serveIssuerMetadata(t, false, func(identifier string) (string, string) {
			signer, err := jose.NewSigner(
				jose.SigningKey{Algorithm: jose.RS256, Key: leafKey},
				(&jose.SignerOptions{}).WithType(signedIssuerMetadataJWTType).
					WithHeader("x5c", []string{base64.StdEncoding.EncodeToString(leafDER)}),
			)
			if err != nil {
				t.Fatal(err)
			}
			compact, err := jwt.Signed(signer).Claims(signedMetadataClaims(identifier)).Serialize()
			if err != nil {
				t.Fatal(err)
			}
			return "application/jwt", compact
		})

		_, err = signedMetadataReceiver(client, fixture, nil).FetchIssuerMetadata(mustURIField(t, serverURL), types.Oid4vci)
		if test.wantErr {
			if !errors.Is(err, ErrIssuerMetadataSignatureInvalid) || !errors.Is(err, commonjose.ErrVerificationKeyTooWeak) {
				t.Fatalf("RSA-%d: err = %v, want ErrIssuerMetadataSignatureInvalid wrapping ErrVerificationKeyTooWeak", test.bits, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("RSA-%d: err = %v", test.bits, err)
		}
	}
}
