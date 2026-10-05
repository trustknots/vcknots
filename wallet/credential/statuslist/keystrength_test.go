package statuslist

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"testing"

	"github.com/go-jose/go-jose/v4"

	commonjose "github.com/trustknots/vcknots/wallet/common/jose"
)

// signRS256 signs claims as a Status List Token under an RSA key.
func signRS256(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType(statusListTokenType).WithHeader("kid", "rsa"))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	object, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := object.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

// TestCheckReferenceRefusesAnRSAKeyBelow2048Bits covers RFC 7518 Section 3.3:
// "A key of size 2048 bits or larger MUST be used with these algorithms". A
// Status List Token signed under a shorter RSA key is not read, even when the
// key resolution hook returns that key.
func TestCheckReferenceRefusesAnRSAKeyBelow2048Bits(t *testing.T) {
	for _, test := range []struct {
		bits    int
		wantErr bool
	}{
		{bits: 1024, wantErr: true},
		{bits: 2048, wantErr: false},
	} {
		h := newHarness(t)
		key, err := rsa.GenerateKey(rand.Reader, test.bits)
		if err != nil {
			t.Fatal(err)
		}
		h.serveToken(signRS256(t, key, defaultClaims(h.uri)))
		status, err := h.checker(jose.JSONWebKey{Key: &key.PublicKey, KeyID: "rsa"}).
			CheckReference(context.Background(), testIssuer, h.reference(0))
		if !test.wantErr {
			if err != nil || status == nil {
				t.Fatalf("RSA-%d: status = %+v, err = %v", test.bits, status, err)
			}
			continue
		}
		if status != nil {
			t.Fatalf("RSA-%d: status = %+v, want nil", test.bits, status)
		}
		assertSentinel(t, err, ErrStatusListSignatureInvalid)
		if !errors.Is(err, commonjose.ErrVerificationKeyTooWeak) {
			t.Fatalf("RSA-%d: err = %v, want it to name the weak key", test.bits, err)
		}
	}
}
