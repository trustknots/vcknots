package issuerkeys

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

// TestDomainLinkageRefusesAnRSAKeyBelow2048Bits covers RFC 7518 Section 3.3:
// "A key of size 2048 bits or larger MUST be used with these algorithms". A
// Domain Linkage Credential signed under a shorter RSA key does not bind the
// DID, however well formed it is otherwise.
func TestDomainLinkageRefusesAnRSAKeyBelow2048Bits(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		bits      int
		wantBound bool
	}{
		{bits: 1024, wantBound: false},
		{bits: 2048, wantBound: true},
	} {
		private, err := rsa.GenerateKey(rand.Reader, test.bits)
		if err != nil {
			t.Fatal(err)
		}
		key := testKey{private: private, public: jose.JSONWebKey{Key: &private.PublicKey}, alg: jose.RS256}
		origin := newTestOrigin(t)
		didValue := didJWK(t, key.public)
		header, claims := domainLinkage(didValue, didValue+"#0", origin.url())
		origin.json(t, didConfigurationPath, map[string]any{
			"@context":    "https://identity.foundation/.well-known/did-configuration/v1",
			"linked_dids": []any{signJWT(t, key, header, claims)},
		})
		resolver := origin.resolver(allMechanisms())
		bound, err := resolver.didConfigurationBinds(context.Background(), didValue, Request{
			Issuer:           didValue,
			CredentialFormat: FormatJWTVCJSON,
			CredentialIssuer: origin.url(),
		})
		if err != nil || bound != test.wantBound {
			t.Fatalf("RSA-%d: didConfigurationBinds = %v, %v; want %v", test.bits, bound, err, test.wantBound)
		}
	}
}
