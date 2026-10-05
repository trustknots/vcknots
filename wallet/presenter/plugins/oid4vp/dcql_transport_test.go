package oid4vp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/presenter/types"
)

func TestOid4vpPresenter_PresentDCQL_SendsAllQueriesInOneResponse(t *testing.T) {
	p, endpoint, forms, calls := dcqlTransportEndpoint(t)
	want := map[string][]string{
		"identity": {"identity-presentation"},
		"accounts": {"first-account-presentation", "second-account-presentation"},
	}
	redirect, err := sendDCQLForTest(p, endpoint, want, &types.PresentationRequest{State: "state +/&="})
	if err != nil {
		t.Fatalf("PresentDCQL() error = %v", err)
	}
	if redirect != "https://verifier.example/complete" {
		t.Fatalf("redirect = %q", redirect)
	}
	form := requireDCQLForm(t, forms, calls)
	if len(form) != 2 || form.Get("state") != "state +/&=" {
		t.Fatalf("expected only vp_token and original state, got %v", form)
	}
	var got map[string][]string
	if err := json.Unmarshal([]byte(form.Get("vp_token")), &got); err != nil {
		t.Fatalf("vp_token must be a JSON object of arrays: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("vp_token = %#v, want %#v", got, want)
	}
}

func TestOid4vpPresenter_PresentDCQL_RejectsInvalidInputBeforeNetwork(t *testing.T) {
	tests := []struct {
		name    string
		tokens  map[string][]string
		request *types.PresentationRequest
	}{
		{name: "nil request", tokens: map[string][]string{"identity": {"token"}}},
		{name: "nil vp_token", request: &types.PresentationRequest{}},
		{name: "empty query id", tokens: map[string][]string{"": {"token"}}, request: &types.PresentationRequest{}},
		{name: "nil token list", tokens: map[string][]string{"identity": nil}, request: &types.PresentationRequest{}},
		{name: "empty token list", tokens: map[string][]string{"identity": {}}, request: &types.PresentationRequest{}},
		{name: "empty token", tokens: map[string][]string{"identity": {""}}, request: &types.PresentationRequest{}},
		{name: "empty token after valid token", tokens: map[string][]string{"identity": {"valid", ""}}, request: &types.PresentationRequest{}},
		{name: "invalid query alongside valid query", tokens: map[string][]string{"identity": {"valid"}, "account": {}}, request: &types.PresentationRequest{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, endpoint, _, calls := dcqlTransportEndpoint(t)
			redirect, err := sendDCQLForTest(p, endpoint, tt.tokens, tt.request)
			if err == nil || redirect != "" {
				t.Fatalf("PresentDCQL() = (%q, %v), want rejection", redirect, err)
			}
			if got := calls.Load(); got != 0 {
				t.Fatalf("invalid input caused %d network requests", got)
			}
		})
	}
}

func TestOid4vpPresenter_PresentDCQL_LegacyPresentKeepsSingleQuery(t *testing.T) {
	p, endpoint, forms, calls := dcqlTransportEndpoint(t)
	redirect, err := p.Present(types.Oid4vp, endpoint, []byte("single-presentation"), &types.PresentationRequest{
		CredentialQueryID: "legacy-query",
		State:             "legacy-state",
	})
	if err != nil {
		t.Fatalf("Present() error = %v", err)
	}
	if redirect != "https://verifier.example/complete" {
		t.Fatalf("redirect = %q", redirect)
	}
	form := requireDCQLForm(t, forms, calls)
	var got map[string][]string
	if err := json.Unmarshal([]byte(form.Get("vp_token")), &got); err != nil {
		t.Fatalf("decode vp_token: %v", err)
	}
	want := map[string][]string{"legacy-query": {"single-presentation"}}
	if !reflect.DeepEqual(got, want) || form.Get("state") != "legacy-state" || len(form) != 2 {
		t.Fatalf("legacy response changed: %v", form)
	}
}

func TestOid4vpPresenter_PresentDCQL_EncryptedResponsePreservesAllQueries(t *testing.T) {
	recipient, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate recipient key: %v", err)
	}
	p, endpoint, forms, calls := dcqlTransportEndpoint(t)
	want := map[string][]string{
		"identity": {"identity-presentation"},
		"accounts": {"first-account-presentation", "second-account-presentation"},
	}
	redirect, err := sendDCQLForTest(p, endpoint, want, &types.PresentationRequest{
		State: "encrypted-state",
		ClientMetadata: &VerifierMetadata{
			AuthorizationEncryptedResponseAlg:   string(jose.ECDH_ES),
			EncryptedResponseEncValuesSupported: []string{"A256GCM"},
			Jwks: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
				Key: &recipient.PublicKey, KeyID: "verifier-encryption", Use: "enc", Algorithm: string(jose.ECDH_ES),
			}}},
		},
	})
	if err != nil {
		t.Fatalf("PresentDCQL() error = %v", err)
	}
	if redirect != "https://verifier.example/complete" {
		t.Fatalf("redirect = %q", redirect)
	}
	form := requireDCQLForm(t, forms, calls)
	if len(form) != 1 || form.Get("response") == "" {
		t.Fatalf("expected only encrypted response form field, got %v", form)
	}
	jwe, err := jose.ParseEncrypted(form.Get("response"), []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		t.Fatalf("parse response JWE: %v", err)
	}
	if jwe.Header.KeyID != "verifier-encryption" {
		t.Fatalf("JWE kid = %q", jwe.Header.KeyID)
	}
	plaintext, err := jwe.Decrypt(recipient)
	if err != nil {
		t.Fatalf("decrypt response JWE: %v", err)
	}
	var payload struct {
		VPToken map[string][]string `json:"vp_token"`
		State   string              `json:"state"`
	}
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		t.Fatalf("decode authorization response: %v", err)
	}
	if !reflect.DeepEqual(payload.VPToken, want) || payload.State != "encrypted-state" {
		t.Fatalf("decrypted response = %#v", payload)
	}
}

func dcqlTransportEndpoint(t *testing.T) (*Oid4vpPresenter, url.URL, <-chan url.Values, *atomic.Int32) {
	t.Helper()
	forms := make(chan url.Values, 8)
	calls := &atomic.Int32{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("unexpected request: method=%s content-type=%q", r.Method, r.Header.Get("Content-Type"))
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse response form: %v", err)
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		select {
		case forms <- r.PostForm:
		default:
			t.Error("unexpected additional authorization response")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"redirect_uri":"https://verifier.example/complete"}`))
	}))
	t.Cleanup(server.Close)
	endpoint, err := url.Parse(server.URL + "/response")
	if err != nil {
		t.Fatalf("parse verifier endpoint: %v", err)
	}
	return &Oid4vpPresenter{HTTPClient: server.Client()}, *endpoint, forms, calls
}

func requireDCQLForm(t *testing.T, forms <-chan url.Values, calls *atomic.Int32) url.Values {
	t.Helper()
	if got := calls.Load(); got != 1 {
		t.Fatalf("authorization response POST count = %d, want 1", got)
	}
	select {
	case form := <-forms:
		return form
	default:
		t.Fatal("verifier did not receive an authorization response")
		return nil
	}
}
