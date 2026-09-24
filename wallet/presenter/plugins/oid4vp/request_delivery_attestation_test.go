package oid4vp

import (
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/trustknots/vcknots/wallet/presenter/types"
	"github.com/trustknots/vcknots/wallet/profile"
)

func presenterForDelivery(f *requestObjectFixture, p profile.Profile) *Oid4vpPresenter {
	options := f.options()
	return &Oid4vpPresenter{
		HTTPClient:              f.server.Client(),
		RequestObjectValidation: &options,
		Profile:                 p,
	}
}

func parseRequestByValue(t *testing.T, f *requestObjectFixture, p profile.Profile, attested bool) (*CredentialPresentationRequest, error) {
	t.Helper()
	return parseRequestObjectWithSourceForTest(presenterForDelivery(f, p), f.signWithRoot(t, f.claims(), false), types.RequestObjectSource{
		ClientID:             f.clientID(),
		DeliveredByReference: attested,
	})
}

func parseRequestByReference(t *testing.T, f *requestObjectFixture, p profile.Profile) (*CredentialPresentationRequest, error) {
	t.Helper()
	f.mu.Lock()
	f.requestObject = []byte(f.signWithRoot(t, f.claims(), false))
	f.mu.Unlock()
	uri := "openid4vp://authorize?" + url.Values{
		"client_id":   {f.clientID()},
		"request_uri": {f.server.URL + "/request-object"},
	}.Encode()
	return presenterForDelivery(f, p).ParsePresentationRequest(uri)
}

// TestHAIPRequestDeliveryAttestation covers the caller attestation that lets an
// application pass a Request Object it fetched through request_uri by value
// while satisfying the HAIP §5.1 delivery-by-reference requirement.
func TestHAIPRequestDeliveryAttestation(t *testing.T) {
	t.Run("by value with attestation is accepted and recorded", func(t *testing.T) {
		f := newRequestObjectFixture(t)
		req, err := parseRequestByValue(t, f, profile.HAIP, true)
		if err != nil {
			t.Fatalf("HAIP with DeliveredByReference must accept the Request Object: %v", err)
		}
		proof := req.RequestObjectVerification
		if proof == nil {
			t.Fatal("missing RequestObjectVerification")
		}
		if !proof.DeliveryAttested {
			t.Errorf("DeliveryAttested = false, want true")
		}
		if proof.Delivery != "value" {
			t.Errorf("Delivery = %q, want value", proof.Delivery)
		}
	})

	t.Run("by value without attestation is rejected", func(t *testing.T) {
		f := newRequestObjectFixture(t)
		_, err := parseRequestByValue(t, f, profile.HAIP, false)
		if err == nil || !strings.Contains(err.Error(), "request_uri") {
			t.Fatalf("HAIP must reject a by-value Request Object without attestation: %v", err)
		}
	})

	t.Run("request_uri is recorded as delivered by reference", func(t *testing.T) {
		f := newRequestObjectFixture(t)
		req, err := parseRequestByReference(t, f, profile.HAIP)
		if err != nil {
			t.Fatalf("HAIP request_uri must be accepted: %v", err)
		}
		proof := req.RequestObjectVerification
		if proof == nil {
			t.Fatal("missing RequestObjectVerification")
		}
		if proof.DeliveryAttested {
			t.Errorf("DeliveryAttested = true for request_uri, want false")
		}
		if proof.Delivery != "reference" {
			t.Errorf("Delivery = %q, want reference", proof.Delivery)
		}
	})

	t.Run("Final ignores the attestation", func(t *testing.T) {
		f := newRequestObjectFixture(t)
		if _, err := parseRequestByValue(t, f, profile.Final, false); err != nil {
			t.Fatalf("Final must accept a by-value Request Object without attestation: %v", err)
		}
		req, err := parseRequestByValue(t, f, profile.Final, true)
		if err != nil {
			t.Fatalf("Final must accept a by-value Request Object with attestation: %v", err)
		}
		proof := req.RequestObjectVerification
		if proof == nil {
			t.Fatal("missing RequestObjectVerification")
		}
		if proof.Delivery != "value" {
			t.Errorf("Delivery = %q, want value", proof.Delivery)
		}
		if proof.DeliveryAttested {
			t.Errorf("Final must not mark the HAIP-only attestation as used: %+v", proof)
		}
	})
}

// TestDeliveryAttestationDoesNotSuppressWalletNonceMismatch proves the
// attestation is scoped to the HAIP delivery check: it never stands in for the
// wallet_nonce echo the caller states it sent.
func TestDeliveryAttestationDoesNotSuppressWalletNonceMismatch(t *testing.T) {
	f := newRequestObjectFixture(t)
	claims := f.claims()
	claims["wallet_nonce"] = "wrong-nonce"
	_, err := parseRequestObjectWithSourceForTest(presenterForDelivery(f, profile.HAIP), f.signWithRoot(t, claims, false), types.RequestObjectSource{
		ClientID:             f.clientID(),
		DeliveredByReference: true,
		WalletNonce:          "expected-nonce",
	})
	if !errors.Is(err, ErrRequestObjectWalletNonceMismatch) {
		t.Fatalf("attestation must not suppress wallet_nonce mismatch: %v", err)
	}
}
