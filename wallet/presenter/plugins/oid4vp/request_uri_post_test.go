package oid4vp

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"testing"
)

// capturedRequestURIForm records the request_uri POST fields without exposing
// the mutex-protected storage to readers.
type capturedRequestURIForm struct {
	mu          sync.Mutex
	method      string
	accept      string
	contentType string
	nonce       string
	metadata    string
	hasMetadata bool
}

type capturedRequestURIValues struct {
	method      string
	accept      string
	contentType string
	nonce       string
	metadata    string
	hasMetadata bool
}

func (c *capturedRequestURIForm) set(r *http.Request) {
	_ = r.ParseForm()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.method = r.Method
	c.accept = r.Header.Get("Accept")
	c.contentType = r.Header.Get("Content-Type")
	c.nonce = r.Form.Get("wallet_nonce")
	c.metadata = r.Form.Get("wallet_metadata")
	_, c.hasMetadata = r.Form["wallet_metadata"]
}

func (c *capturedRequestURIForm) snapshot() capturedRequestURIValues {
	c.mu.Lock()
	defer c.mu.Unlock()
	return capturedRequestURIValues{
		method: c.method, accept: c.accept, contentType: c.contentType,
		nonce: c.nonce, metadata: c.metadata, hasMetadata: c.hasMetadata,
	}
}

// echoNonceHandler parses the POST form and returns a signed Request Object
// whose wallet_nonce claim echoes the received value.
func (f *requestObjectFixture) echoNonceHandler(t *testing.T, captured *capturedRequestURIForm, nonceOverride func(string) string) {
	f.setRequestObjectHandler(func(w http.ResponseWriter, r *http.Request) {
		captured.set(r)
		claims := f.claims()
		if nonceOverride != nil {
			claims["wallet_nonce"] = nonceOverride(r.Form.Get("wallet_nonce"))
		} else {
			claims["wallet_nonce"] = r.Form.Get("wallet_nonce")
		}
		w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
		_, _ = w.Write([]byte(f.sign(t, claims, nil)))
	})
}

func (f *requestObjectFixture) parseRequestURIPost(t *testing.T, p *Oid4vpPresenter) (*CredentialPresentationRequest, error) {
	t.Helper()
	uri := "openid4vp://authorize?" + url.Values{
		"client_id":          {f.clientID()},
		"request_uri":        {f.server.URL + "/request-object"},
		"request_uri_method": {"post"},
	}.Encode()
	return p.ParsePresentationRequest(uri)
}

func TestFinalRequestURIPostSendsWalletNonceAndMetadata(t *testing.T) {
	f := newRequestObjectFixture(t)
	const nonce = "fixed-wallet-nonce"
	captured := &capturedRequestURIForm{}
	f.echoNonceHandler(t, captured, nil)

	p := f.presenter()
	p.RequestURINonce = func() (string, error) { return nonce, nil }
	p.WalletMetadata = map[string]any{"vp_formats_supported": map[string]any{"dc+sd-jwt": map[string]any{}}}

	req, err := f.parseRequestURIPost(t, p)
	if err != nil {
		t.Fatalf("ParsePresentationRequest: %v", err)
	}
	if req.RequestObjectVerification == nil || req.RequestObjectVerification.WalletNonce != nonce {
		t.Fatalf("WalletNonce not recorded: %+v", req.RequestObjectVerification)
	}

	got := captured.snapshot()
	if got.method != http.MethodPost {
		t.Errorf("method = %q, want POST", got.method)
	}
	if got.accept != "application/oauth-authz-req+jwt" {
		t.Errorf("Accept = %q, want application/oauth-authz-req+jwt", got.accept)
	}
	if got.contentType != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q, want application/x-www-form-urlencoded", got.contentType)
	}
	if got.nonce != nonce {
		t.Errorf("wallet_nonce = %q, want %q", got.nonce, nonce)
	}
	if !got.hasMetadata {
		t.Fatal("wallet_metadata parameter missing from POST body")
	}
	var metadata map[string]any
	if err := json.Unmarshal([]byte(got.metadata), &metadata); err != nil {
		t.Fatalf("wallet_metadata is not a JSON object: %v (%q)", err, got.metadata)
	}
	if _, ok := metadata["vp_formats_supported"]; !ok {
		t.Errorf("wallet_metadata missing configured entry: %v", metadata)
	}
}

func TestFinalRequestURIPostOmitsUnsetWalletMetadata(t *testing.T) {
	f := newRequestObjectFixture(t)
	captured := &capturedRequestURIForm{}
	f.echoNonceHandler(t, captured, nil)

	p := f.presenter()
	p.RequestURINonce = func() (string, error) { return "nonce", nil }

	if _, err := f.parseRequestURIPost(t, p); err != nil {
		t.Fatalf("ParsePresentationRequest: %v", err)
	}
	got := captured.snapshot()
	if got.hasMetadata {
		t.Errorf("wallet_metadata must be omitted when unset, got %q", got.metadata)
	}
	if got.nonce == "" {
		t.Error("wallet_nonce must always be sent on Final request_uri POST")
	}
}

func TestFinalRequestURIPostRejectsWalletNonceMismatch(t *testing.T) {
	const nonce = "expected-wallet-nonce"
	cases := map[string]func(string) string{
		"different": func(string) string { return "different-wallet-nonce" },
		"missing":   func(string) string { return "" },
	}
	for name, override := range cases {
		t.Run(name, func(t *testing.T) {
			f := newRequestObjectFixture(t)
			captured := &capturedRequestURIForm{}
			f.echoNonceHandler(t, captured, override)

			p := f.presenter()
			p.RequestURINonce = func() (string, error) { return nonce, nil }

			_, err := f.parseRequestURIPost(t, p)
			if err == nil {
				t.Fatal("mismatched wallet_nonce must be rejected")
			}
			if !errors.Is(err, ErrRequestObjectWalletNonceMismatch) {
				t.Fatalf("unexpected error: %v", err)
			}
			var authzErr *AuthorizationRequestError
			if !errors.As(err, &authzErr) || authzErr.Code != InvalidRequestError {
				t.Fatalf("want invalid_request, got %v", err)
			}
		})
	}
}

func TestFinalRequestURIGETIgnoresWalletNonceClaim(t *testing.T) {
	f := newRequestObjectFixture(t)
	claims := f.claims()
	claims["wallet_nonce"] = "unsolicited-nonce"
	req, err := f.parseRequest(t, claims, requestFixtureOptions{Delivery: deliverByReference})
	if err != nil {
		t.Fatalf("GET must ignore a present wallet_nonce claim: %v", err)
	}
	if req.RequestObjectVerification == nil || req.RequestObjectVerification.WalletNonce != "" {
		t.Fatalf("GET must record no sent nonce: %+v", req.RequestObjectVerification)
	}
}
