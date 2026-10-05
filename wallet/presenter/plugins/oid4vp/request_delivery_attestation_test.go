package oid4vp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sync/atomic"
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

func parseRequestByValue(t *testing.T, f *requestObjectFixture, p profile.Profile) (*CredentialPresentationRequest, error) {
	t.Helper()
	return parseRequestObjectWithSourceForTest(presenterForDelivery(f, p), f.signWithRoot(t, f.claims(), false), types.RequestObjectSource{
		ClientID: f.clientID(),
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

// TestHAIPRequestDelivery covers HAIP 1.0 §5.1 ("Signed Authorization Requests
// MUST be used by utilizing JAR with the request_uri parameter"): only a
// request_uri this library fetched itself satisfies it, and a caller cannot
// state a delivery the library did not observe.
func TestHAIPRequestDelivery(t *testing.T) {
	t.Run("a Request Object passed by value is refused", func(t *testing.T) {
		f := newRequestObjectFixture(t)
		_, err := parseRequestByValue(t, f, profile.HAIP())
		if !errors.Is(err, ErrRequestURIRequired) {
			t.Fatalf("HAIP must refuse a by-value Request Object: %v", err)
		}
	})

	t.Run("the request parameter is refused before any fetch", func(t *testing.T) {
		f := newRequestObjectFixture(t)
		var fetched atomic.Int32
		f.setRequestObjectHandler(func(w http.ResponseWriter, _ *http.Request) {
			fetched.Add(1)
			http.NotFound(w, nil)
		})
		_, err := f.parseRequest(t, f.claims(), requestFixtureOptions{Profile: profile.HAIP(), Delivery: deliverByValue})
		if !errors.Is(err, ErrRequestURIRequired) {
			t.Fatalf("HAIP must refuse the request parameter: %v", err)
		}
		if fetched.Load() != 0 {
			t.Fatal("a refused by-value request must not reach the network")
		}
	})

	t.Run("request_uri is recorded as delivered by reference", func(t *testing.T) {
		f := newRequestObjectFixture(t)
		req, err := parseRequestByReference(t, f, profile.HAIP())
		if err != nil {
			t.Fatalf("HAIP request_uri must be accepted: %v", err)
		}
		proof := req.RequestObjectVerification
		if proof == nil {
			t.Fatal("missing RequestObjectVerification")
		}
		if proof.Delivery != "reference" {
			t.Errorf("Delivery = %q, want reference", proof.Delivery)
		}
	})

	t.Run("Final accepts a Request Object passed by value", func(t *testing.T) {
		f := newRequestObjectFixture(t)
		req, err := parseRequestByValue(t, f, profile.Final())
		if err != nil {
			t.Fatalf("Final must accept a by-value Request Object: %v", err)
		}
		if proof := req.RequestObjectVerification; proof == nil || proof.Delivery != "value" || proof.WalletNonce != "" {
			t.Fatalf("a by-value Request Object is recorded as delivered by value without a wallet_nonce: %+v", proof)
		}
	})
}

// TestByValueRequestObjectIgnoresUnsentWalletNonce: a wallet_nonce claim in a
// Request Object passed by value is not a nonce this library sent, so it binds
// nothing (OID4VP 1.0 §5.10.1 binds only the nonce "the Wallet passed ... in
// the POST request") and is not reported as one.
func TestByValueRequestObjectIgnoresUnsentWalletNonce(t *testing.T) {
	f := newRequestObjectFixture(t)
	claims := f.claims()
	claims["wallet_nonce"] = "nonce-from-elsewhere"
	req, err := parseRequestObjectWithSourceForTest(presenterForDelivery(f, profile.Final()), f.signWithRoot(t, claims, false), types.RequestObjectSource{ClientID: f.clientID()})
	if err != nil {
		t.Fatalf("ParseRequestObject: %v", err)
	}
	if req.RequestObjectVerification.WalletNonce != "" {
		t.Fatalf("WalletNonce = %q, want empty for a nonce this library did not send", req.RequestObjectVerification.WalletNonce)
	}
}

// draft24PostFixture serves a Draft 24 Request Object that echoes the
// wallet_nonce of the request_uri POST, or echoNonce when it is set.
func draft24PostFixture(t *testing.T, captured *capturedRequestURIForm, echoNonce string) *requestObjectFixture {
	t.Helper()
	f := newRequestObjectFixture(t, "verifier.example")
	f.setRequestObjectHandler(func(w http.ResponseWriter, r *http.Request) {
		captured.set(r)
		claims := draft24X509Claims(f)
		claims["wallet_nonce"] = r.Form.Get("wallet_nonce")
		if echoNonce != "" {
			claims["wallet_nonce"] = echoNonce
		}
		w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
		_, _ = w.Write([]byte(f.sign(t, claims, nil)))
	})
	return f
}

func draft24RequestURIPost(f *requestObjectFixture) string {
	return "openid4vp://authorize?" + url.Values{
		"client_id":          {"x509_san_dns:verifier.example"},
		"request_uri":        {f.server.URL + "/request-object"},
		"request_uri_method": {"post"},
	}.Encode()
}

// TestDraft24RequestURIPostSendsWalletNonceAndMetadata covers Draft 24 §5.11:
// the POST carries the Wallet's wallet_metadata and a fresh wallet_nonce, and
// "if the Wallet passed a wallet_nonce in the POST request, the Wallet MUST
// validate whether the request object contains the respective nonce value".
func TestDraft24RequestURIPostSendsWalletNonceAndMetadata(t *testing.T) {
	t.Run("the POST carries wallet_nonce and wallet_metadata", func(t *testing.T) {
		captured := &capturedRequestURIForm{}
		f := draft24PostFixture(t, captured, "")
		p := f.presenter()
		p.RequestURINonce = func() (string, error) { return "draft24-wallet-nonce", nil }
		p.WalletMetadata = map[string]any{"vp_formats_supported": map[string]any{"vc+sd-jwt": map[string]any{}}}

		request, err := parseDraft24ForTest(p, draft24RequestURIPost(f))
		if err != nil {
			t.Fatalf("ParseDraft24Request: %v", err)
		}
		got := captured.snapshot()
		if got.method != http.MethodPost || got.accept != "application/oauth-authz-req+jwt" {
			t.Fatalf("method %q Accept %q, want POST application/oauth-authz-req+jwt", got.method, got.accept)
		}
		if got.nonce != "draft24-wallet-nonce" {
			t.Fatalf("wallet_nonce = %q, want the generated nonce", got.nonce)
		}
		var metadata map[string]any
		if err := json.Unmarshal([]byte(got.metadata), &metadata); err != nil || metadata["vp_formats_supported"] == nil {
			t.Fatalf("wallet_metadata = %q, want the configured metadata", got.metadata)
		}
		if proof := request.RequestObjectVerification; proof == nil || proof.WalletNonce != "draft24-wallet-nonce" || proof.Delivery != "reference" {
			t.Fatalf("the sent wallet_nonce and delivery are not recorded: %+v", proof)
		}
	})

	t.Run("without WalletMetadata the parameter is omitted", func(t *testing.T) {
		captured := &capturedRequestURIForm{}
		f := draft24PostFixture(t, captured, "")
		if _, err := parseDraft24ForTest(f.presenter(), draft24RequestURIPost(f)); err != nil {
			t.Fatalf("ParseDraft24Request: %v", err)
		}
		if got := captured.snapshot(); got.hasMetadata || got.nonce == "" {
			t.Fatalf("POST body = %+v, want a wallet_nonce and no wallet_metadata", got)
		}
	})

	t.Run("OmitWalletNonce sends no wallet_nonce and checks no echo", func(t *testing.T) {
		captured := &capturedRequestURIForm{}
		f := draft24PostFixture(t, captured, "")
		p := f.presenter()
		p.OmitWalletNonce = true
		request, err := parseDraft24ForTest(p, draft24RequestURIPost(f))
		if err != nil {
			t.Fatalf("ParseDraft24Request: %v", err)
		}
		if got := captured.snapshot(); got.method != http.MethodPost || got.nonce != "" {
			t.Fatalf("POST body = %+v, want a POST without wallet_nonce", got)
		}
		if proof := request.RequestObjectVerification; proof == nil || proof.WalletNonce != "" {
			t.Fatalf("no wallet_nonce was sent, so none is recorded: %+v", proof)
		}
	})

	t.Run("a Request Object that does not echo the nonce is refused", func(t *testing.T) {
		captured := &capturedRequestURIForm{}
		f := draft24PostFixture(t, captured, "another-nonce")
		_, err := parseDraft24ForTest(f.presenter(), draft24RequestURIPost(f))
		if !errors.Is(err, ErrRequestObjectWalletNonceMismatch) {
			t.Fatalf("a Draft 24 Request Object must echo the wallet_nonce: %v", err)
		}
	})

	t.Run("request_uri_method is case-sensitive", func(t *testing.T) {
		f := newRequestObjectFixture(t, "verifier.example")
		uri := "openid4vp://authorize?" + url.Values{
			"client_id":          {"x509_san_dns:verifier.example"},
			"request_uri":        {f.server.URL + "/request-object"},
			"request_uri_method": {"POST"},
		}.Encode()
		_, err := (&Oid4vpPresenter{HTTPClient: f.server.Client()}).ParseDraft24Request(context.Background(), uri)
		assertAuthzErrorCode(t, err, InvalidRequestURIMethodError)
	})
}

// TestRequestURIPolicy covers RequestObjectValidationOptions.RequestURIPolicy:
// the Wallet associates request_uri with the Client Identifier before it
// contacts the endpoint, and refuses the request when the link cannot be
// established (OpenID4VP 1.0, "Authorization Requests with Request URI").
func TestRequestURIPolicy(t *testing.T) {
	type call struct{ clientID, requestURI string }
	for _, draft24 := range []bool{false, true} {
		name := "final"
		if draft24 {
			name = "draft24"
		}
		t.Run(name, func(t *testing.T) {
			f := newRequestObjectFixture(t, "verifier.example")
			var fetched atomic.Int32
			f.setRequestObjectHandler(func(w http.ResponseWriter, _ *http.Request) {
				fetched.Add(1)
				claims := f.claims()
				if draft24 {
					claims = draft24X509Claims(f)
				}
				_, _ = w.Write([]byte(f.sign(t, claims, nil)))
			})
			clientID := f.clientID()
			if draft24 {
				clientID = "x509_san_dns:verifier.example"
			}
			requestURI := f.server.URL + "/request-object"
			uri := "openid4vp://authorize?" + url.Values{"client_id": {clientID}, "request_uri": {requestURI}}.Encode()
			parse := func(policy func(string, string) error) error {
				options := f.options()
				options.RequestURIPolicy = policy
				p := &Oid4vpPresenter{HTTPClient: f.server.Client(), RequestObjectValidation: &options}
				if draft24 {
					_, err := p.ParseDraft24Request(context.Background(), uri)
					return err
				}
				_, err := p.ParseRequest(context.Background(), uri)
				return err
			}

			var seen []call
			if err := parse(func(clientID, requestURI string) error {
				seen = append(seen, call{clientID, requestURI})
				return nil
			}); err != nil {
				t.Fatalf("an associated request_uri must be accepted: %v", err)
			}
			if len(seen) != 1 || seen[0] != (call{clientID, requestURI}) {
				t.Fatalf("policy saw %+v, want the outer client_id and request_uri", seen)
			}
			before := fetched.Load()
			err := parse(func(string, string) error { return errors.New("not this verifier's endpoint") })
			if !errors.Is(err, ErrRequestURINotAssociated) {
				t.Fatalf("want ErrRequestURINotAssociated, got %v", err)
			}
			if fetched.Load() != before {
				t.Fatal("a request_uri the policy refused must not be fetched")
			}
		})
	}
}
