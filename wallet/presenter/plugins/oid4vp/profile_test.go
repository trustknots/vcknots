package oid4vp

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/internal/testutil"
	"github.com/trustknots/vcknots/wallet/presenter/types"
	"github.com/trustknots/vcknots/wallet/profile"
)

// TestFinalAndHAIPProfileParseCheckpoints exercises each HAIP constraint in
// both directions: the Final profile accepts the input and the HAIP profile
// rejects it.
func TestFinalAndHAIPProfileParseCheckpoints(t *testing.T) {
	t.Run("unknown profile value is rejected before parsing", func(t *testing.T) {
		f := newRequestObjectFixture(t)
		claims := f.claims()
		for _, unknown := range []profile.Profile{"HAIP", "draft24", "Final"} {
			_, err := f.parseRequest(t, claims, requestFixtureOptions{Profile: unknown, Delivery: deliverByValue})
			if err == nil || !strings.Contains(err.Error(), "unknown protocol profile") {
				t.Fatalf("profile %q: want unknown profile error, got %v", unknown, err)
			}
		}
	})

	t.Run("AllowHTTP under HAIP", func(t *testing.T) {
		f := newRequestObjectFixture(t)
		claims := f.claims()
		if _, err := f.parseRequest(t, claims, requestFixtureOptions{Profile: profile.Final, Delivery: deliverByReference, AllowHTTP: true}); err != nil {
			t.Fatalf("Final must accept AllowHTTP test policy: %v", err)
		}
		_, err := f.parseRequest(t, claims, requestFixtureOptions{Profile: profile.HAIP, Delivery: deliverByReference, AllowHTTP: true})
		if err == nil || !strings.Contains(err.Error(), "HAIP profile does not permit AllowHTTP or InsecureSkipX509Verify") {
			t.Fatalf("HAIP must reject AllowHTTP: %v", err)
		}
	})

	t.Run("InsecureSkipX509Verify under HAIP", func(t *testing.T) {
		f := newRequestObjectFixture(t)
		claims := f.claims()
		if _, err := f.parseRequest(t, claims, requestFixtureOptions{Profile: profile.Final, Delivery: deliverByReference, Insecure: true}); err == nil {
			// InsecureSkipX509Verify is refused on the Final Request Object path
			// itself, so only assert the HAIP-specific policy error.
			t.Log("Final rejected insecure verify for its own reason")
		}
		_, err := f.parseRequest(t, claims, requestFixtureOptions{Profile: profile.HAIP, Delivery: deliverByReference, Insecure: true})
		if err == nil || !strings.Contains(err.Error(), "HAIP profile does not permit AllowHTTP or InsecureSkipX509Verify") {
			t.Fatalf("HAIP must reject InsecureSkipX509Verify: %v", err)
		}
	})

	t.Run("x509_san_dns under HAIP", func(t *testing.T) {
		f := newRequestObjectFixture(t, "verifier.example")
		claims := f.claims()
		claims["client_id"] = "x509_san_dns:verifier.example"
		claims["response_uri"] = "https://verifier.example/response"
		if _, err := f.parseRequest(t, claims, requestFixtureOptions{Profile: profile.Final, Delivery: deliverByReference}); err != nil {
			t.Fatalf("Final must accept x509_san_dns: %v", err)
		}
		_, err := f.parseRequest(t, claims, requestFixtureOptions{Profile: profile.HAIP, Delivery: deliverByReference})
		if err == nil || !strings.Contains(err.Error(), "x509_hash Client Identifier Prefix") {
			t.Fatalf("HAIP must reject x509_san_dns: %v", err)
		}
	})

	t.Run("request object by value under HAIP", func(t *testing.T) {
		f := newRequestObjectFixture(t)
		claims := f.claims()
		if _, err := f.parseRequest(t, claims, requestFixtureOptions{Profile: profile.Final, Delivery: deliverByValue}); err != nil {
			t.Fatalf("Final must accept a Request Object by value: %v", err)
		}
		_, err := f.parseRequest(t, claims, requestFixtureOptions{Profile: profile.HAIP, Delivery: deliverByValue})
		if err == nil || !strings.Contains(err.Error(), "request_uri") {
			t.Fatalf("HAIP must reject a Request Object by value: %v", err)
		}
	})

	t.Run("plain query under HAIP", func(t *testing.T) {
		f := newRequestObjectFixture(t)
		claims := f.claims()
		claims["client_id"] = "redirect_uri:https://verifier.example/cb"
		claims["response_mode"] = "fragment"
		delete(claims, "response_uri")
		claims["redirect_uri"] = "https://verifier.example/cb"
		if _, err := f.parseRequest(t, claims, requestFixtureOptions{Profile: profile.Final, Delivery: deliverByQuery}); err != nil {
			t.Fatalf("Final must accept a plain query request: %v", err)
		}
		_, err := f.parseRequest(t, claims, requestFixtureOptions{Profile: profile.HAIP, Delivery: deliverByQuery})
		if err == nil || !strings.Contains(err.Error(), "request_uri") {
			t.Fatalf("HAIP must reject a plain query request: %v", err)
		}
	})

	t.Run("response_mode direct_post under HAIP", func(t *testing.T) {
		f := newRequestObjectFixture(t)
		claims := f.claims()
		claims["response_mode"] = "direct_post"
		if _, err := f.parseRequest(t, claims, requestFixtureOptions{Profile: profile.Final, Delivery: deliverByReference}); err != nil {
			t.Fatalf("Final must accept direct_post: %v", err)
		}
		_, err := f.parseRequest(t, claims, requestFixtureOptions{Profile: profile.HAIP, Delivery: deliverByReference})
		if err == nil || !strings.Contains(err.Error(), "response_mode direct_post.jwt") {
			t.Fatalf("HAIP must reject direct_post: %v", err)
		}
	})

	t.Run("dc_api.jwt outside the DC API", func(t *testing.T) {
		f := newRequestObjectFixture(t)
		claims := f.claims()
		claims["response_mode"] = "dc_api.jwt"
		delete(claims, "response_uri")
		claims["redirect_uri"] = "https://verifier.example/cb"
		_, err := f.parseRequest(t, claims, requestFixtureOptions{Profile: profile.HAIP, Delivery: deliverByReference})
		if err == nil || !strings.Contains(err.Error(), "only valid over the Digital Credentials API") {
			t.Fatalf("dc_api.jwt must be refused outside the DC API: %v", err)
		}
	})

	t.Run("DCQL credential format under HAIP", func(t *testing.T) {
		f := newRequestObjectFixture(t)
		claims := f.claims()
		if _, err := f.parseRequest(t, claims, requestFixtureOptions{Profile: profile.Final, Delivery: deliverByReference, DCQLFormat: "jwt_vc_json"}); err != nil {
			t.Fatalf("Final must accept jwt_vc_json: %v", err)
		}
		_, err := f.parseRequest(t, claims, requestFixtureOptions{Profile: profile.HAIP, Delivery: deliverByReference, DCQLFormat: "jwt_vc_json"})
		if err == nil || !strings.Contains(err.Error(), "dc+sd-jwt and mso_mdoc") {
			t.Fatalf("HAIP must reject jwt_vc_json: %v", err)
		}
		_, err = f.parseRequest(t, claims, requestFixtureOptions{Profile: profile.HAIP, Delivery: deliverByReference, DCQLFormat: "vc+sd-jwt"})
		if err == nil || !strings.Contains(err.Error(), "dc+sd-jwt and mso_mdoc") {
			t.Fatalf("HAIP must reject vc+sd-jwt: %v", err)
		}
	})

	t.Run("trust anchor in x5c header under HAIP", func(t *testing.T) {
		f := newRequestObjectFixture(t)
		claims := f.claims()
		if _, err := f.parseRequest(t, claims, requestFixtureOptions{Profile: profile.Final, Delivery: deliverByReference, IncludeRoot: true}); err != nil {
			t.Fatalf("Final must accept a chain that includes the anchor: %v", err)
		}
		_, err := f.parseRequest(t, claims, requestFixtureOptions{Profile: profile.HAIP, Delivery: deliverByReference, IncludeRoot: true})
		if err == nil || !strings.Contains(err.Error(), "trust anchor certificate in the x5c header") {
			t.Fatalf("HAIP must reject the anchor in x5c: %v", err)
		}
	})
}

// TestFinalAndHAIPProfileDraft24Exempt verifies the Draft24 entrypoints are not
// constrained by the HAIP profile.
func TestFinalAndHAIPProfileDraft24Exempt(t *testing.T) {
	f := newRequestObjectFixture(t)
	claims := f.claims()
	// A Draft24-legal request would fail every HAIP checkpoint, yet the Draft24
	// builder must ignore the profile entirely.
	token := f.sign(t, claims, nil)
	uri := "openid4vp://authorize?" + url.Values{"client_id": {claims["client_id"].(string)}, "request": {token}}.Encode()
	p := f.presenter()
	p.Profile = profile.HAIP
	if _, err := parseDraft24ForTest(p, uri); err != nil {
		t.Fatalf("Draft24 must not enforce HAIP: %v", err)
	}
}

type encryptionServer struct {
	server *httptest.Server
	forms  chan url.Values
	calls  *atomic.Int32
}

func newEncryptionServer(t *testing.T) *encryptionServer {
	t.Helper()
	forms := make(chan url.Values, 8)
	calls := &atomic.Int32{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		select {
		case forms <- r.PostForm:
		default:
			t.Error("unexpected additional authorization response")
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	return &encryptionServer{server: server, forms: forms, calls: calls}
}

func (s *encryptionServer) endpoint(t *testing.T) url.URL {
	t.Helper()
	endpoint, err := url.Parse(s.server.URL + "/response")
	if err != nil {
		t.Fatal(err)
	}
	return *endpoint
}

func decryptAuthorizationResponse(t *testing.T, token string, recipient *ecdsa.PrivateKey, alg jose.KeyAlgorithm, enc jose.ContentEncryption) map[string]any {
	t.Helper()
	jwe, err := jose.ParseEncrypted(token, []jose.KeyAlgorithm{alg}, []jose.ContentEncryption{enc})
	if err != nil {
		t.Fatalf("parse response JWE: %v", err)
	}
	plaintext, err := jwe.Decrypt(recipient)
	if err != nil {
		t.Fatalf("decrypt response JWE: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		t.Fatalf("decode authorization response: %v", err)
	}
	return payload
}

func TestPresentDCQLFinalResponseEncryption(t *testing.T) {
	recipient := testutil.NewP256Key(t)
	vpToken := map[string][]string{"pid": {"credential"}}

	t.Run("direct_post.jwt encrypts with the advertised enc and kid", func(t *testing.T) {
		s := newEncryptionServer(t)
		p := &Oid4vpPresenter{HTTPClient: s.server.Client()}
		request := &types.PresentationRequest{
			State: "state-1",
			ClientMetadata: &VerifierMetadata{
				Jwks: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
					Key: &recipient.PublicKey, KeyID: "enc-key", Use: "enc", Algorithm: "ECDH-ES",
				}}},
				EncryptedResponseEncValuesSupported: []string{"A256GCM"},
			},
		}
		if _, err := sendDCQLForTest(p, s.endpoint(t), vpToken, request); err != nil {
			t.Fatal(err)
		}
		if got := s.calls.Load(); got != 1 {
			t.Fatalf("authorization response POST count = %d, want 1", got)
		}
		token := (<-s.forms).Get("response")
		if token == "" {
			t.Fatal("expected an encrypted response form field")
		}
		jwe, err := jose.ParseEncrypted(token, []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A256GCM})
		if err != nil {
			t.Fatalf("parse response JWE: %v", err)
		}
		if jwe.Header.KeyID != "enc-key" {
			t.Fatalf("JWE kid = %q, want enc-key", jwe.Header.KeyID)
		}
		if got := jwe.Header.ExtraHeaders[jose.HeaderKey("enc")]; got != "A256GCM" {
			t.Fatalf("JWE enc = %#v, want A256GCM", got)
		}
		payload := decryptAuthorizationResponse(t, token, recipient, jose.ECDH_ES, jose.A256GCM)
		if payload["state"] != "state-1" {
			t.Fatalf("state = %#v", payload["state"])
		}
	})

	t.Run("first unusable key is skipped for a later EC key", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		s := newEncryptionServer(t)
		p := &Oid4vpPresenter{HTTPClient: s.server.Client()}
		request := &types.PresentationRequest{
			ClientMetadata: &VerifierMetadata{
				Jwks: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
					{Key: &rsaKey.PublicKey, KeyID: "rsa-sig", Use: "sig"},
					{Key: &recipient.PublicKey, KeyID: "ec-enc", Use: "enc", Algorithm: "ECDH-ES"},
				}},
				EncryptedResponseEncValuesSupported: []string{"A128GCM"},
			},
		}
		if _, err := sendDCQLForTest(p, s.endpoint(t), vpToken, request); err != nil {
			t.Fatal(err)
		}
		token := (<-s.forms).Get("response")
		jwe, err := jose.ParseEncrypted(token, []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A128GCM})
		if err != nil {
			t.Fatal(err)
		}
		if jwe.Header.KeyID != "ec-enc" {
			t.Fatalf("JWE kid = %q, want ec-enc", jwe.Header.KeyID)
		}
	})

	t.Run("no usable key errors before any HTTP POST", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		s := newEncryptionServer(t)
		p := &Oid4vpPresenter{HTTPClient: s.server.Client()}
		request := &types.PresentationRequest{
			ClientMetadata: &VerifierMetadata{
				Jwks:                                jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &rsaKey.PublicKey, Use: "sig"}}},
				EncryptedResponseEncValuesSupported: []string{"A128GCM"},
			},
		}
		if _, err := sendDCQLForTest(p, s.endpoint(t), vpToken, request); err == nil {
			t.Fatal("expected no usable encryption key error")
		}
		if got := s.calls.Load(); got != 0 {
			t.Fatalf("invalid encryption caused %d network requests", got)
		}
	})

	t.Run("direct_post sends plaintext vp_token and state", func(t *testing.T) {
		s := newEncryptionServer(t)
		p := &Oid4vpPresenter{HTTPClient: s.server.Client()}
		request := &types.PresentationRequest{State: "plain-state"}
		if _, err := sendDCQLForTest(p, s.endpoint(t), vpToken, request); err != nil {
			t.Fatal(err)
		}
		form := <-s.forms
		if form.Get("response") != "" {
			t.Fatalf("direct_post must not encrypt, got response %q", form.Get("response"))
		}
		if form.Get("state") != "plain-state" {
			t.Fatalf("state = %q", form.Get("state"))
		}
		var got map[string][]string
		if err := json.Unmarshal([]byte(form.Get("vp_token")), &got); err != nil {
			t.Fatalf("decode vp_token: %v", err)
		}
		if len(got["pid"]) != 1 || got["pid"][0] != "credential" {
			t.Fatalf("vp_token = %#v", got)
		}
	})
}

func TestPresentDCQLHAIPResponseEncryption(t *testing.T) {
	recipient := testutil.NewP256Key(t)
	vpToken := map[string][]string{"pid": {"credential"}}

	newHAIPPresenter := func(s *encryptionServer) *Oid4vpPresenter {
		return &Oid4vpPresenter{HTTPClient: s.server.Client(), Profile: profile.HAIP}
	}

	t.Run("ECDH-ES with A128GCM is accepted", func(t *testing.T) {
		s := newEncryptionServer(t)
		request := &types.PresentationRequest{
			ClientMetadata: &VerifierMetadata{
				Jwks:                                jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &recipient.PublicKey, KeyID: "haip-enc", Use: "enc", Algorithm: "ECDH-ES"}}},
				EncryptedResponseEncValuesSupported: []string{"A128GCM"},
			},
		}
		if _, err := sendDCQLForTest(newHAIPPresenter(s), s.endpoint(t), vpToken, request); err != nil {
			t.Fatal(err)
		}
		token := (<-s.forms).Get("response")
		payload := decryptAuthorizationResponse(t, token, recipient, jose.ECDH_ES, jose.A128GCM)
		if payload["vp_token"] == nil {
			t.Fatalf("payload = %#v", payload)
		}
	})

	t.Run("key agreement other than ECDH-ES is rejected", func(t *testing.T) {
		s := newEncryptionServer(t)
		request := &types.PresentationRequest{
			ClientMetadata: &VerifierMetadata{
				Jwks: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
					Key: &recipient.PublicKey, KeyID: "haip-kw", Use: "enc", Algorithm: "ECDH-ES+A128KW",
				}}},
				EncryptedResponseEncValuesSupported: []string{"A128GCM"},
			},
		}
		if _, err := sendDCQLForTest(newHAIPPresenter(s), s.endpoint(t), vpToken, request); err == nil {
			t.Fatal("HAIP must reject ECDH-ES+A128KW")
		}
		if got := s.calls.Load(); got != 0 {
			t.Fatalf("HAIP rejection caused %d network requests", got)
		}
	})

	t.Run("non-AEAD content encryption is rejected", func(t *testing.T) {
		s := newEncryptionServer(t)
		request := &types.PresentationRequest{
			ClientMetadata: &VerifierMetadata{
				Jwks:                                jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &recipient.PublicKey, Use: "enc", Algorithm: "ECDH-ES"}}},
				EncryptedResponseEncValuesSupported: []string{"A128CBC-HS256"},
			},
		}
		if _, err := sendDCQLForTest(newHAIPPresenter(s), s.endpoint(t), vpToken, request); err == nil {
			t.Fatal("HAIP must reject A128CBC-HS256")
		}
		if got := s.calls.Load(); got != 0 {
			t.Fatalf("HAIP rejection caused %d network requests", got)
		}
	})
}

// TestEncryptedAuthorizationResponseMatchesPresentDCQL proves both
// encryption paths select the same key/alg/enc.
func TestEncryptedAuthorizationResponseMatchesPresentDCQL(t *testing.T) {
	recipient := testutil.NewP256Key(t)
	metadata := &VerifierMetadata{
		Jwks:                                jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &recipient.PublicKey, KeyID: "shared", Use: "enc", Algorithm: "ECDH-ES"}}},
		EncryptedResponseEncValuesSupported: []string{"A256GCM"},
	}
	p := &Oid4vpPresenter{}
	token, err := encryptResponseForTest(p, map[string]any{"vp_token": map[string]any{"pid": []string{"credential"}}}, metadata)
	if err != nil {
		t.Fatal(err)
	}
	jwe, err := jose.ParseEncrypted(token, []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		t.Fatal(err)
	}
	if jwe.Header.KeyID != "shared" {
		t.Fatalf("JWE kid = %q", jwe.Header.KeyID)
	}
}

// dcapiUnsignedInvocation builds an unsigned Digital Credentials API invocation
// with the given Response Mode (OID4VP 1.0 Appendix A.3.1).
func dcapiUnsignedInvocation(t *testing.T, responseMode string) types.DCAPIInvocation {
	t.Helper()
	params := map[string]any{
		"response_type": "vp_token", "response_mode": responseMode, "nonce": "n-1",
		"dcql_query": map[string]any{"credentials": []any{map[string]any{
			"id": "pid", "format": "dc+sd-jwt",
			"meta": map[string]any{"vct_values": []string{"urn:eudi:pid:1"}},
		}}},
	}
	if responseMode == string(OAuthAuthzReqResponseModeDCAPIJWT) {
		params["client_metadata"] = responseEncryptionClientMetadataClaim()
	}
	data, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	return types.DCAPIInvocation{
		Request: types.DCAPIRequest{Protocol: DCAPIProtocolUnsigned, Data: data},
		Origin:  "https://verifier.example",
	}
}

// HAIP §5.2: "The Wallet MUST support the Response Mode dc_api.jwt. The Verifier
// MUST use the Response Mode dc_api.jwt." An unencrypted dc_api response is not
// acceptable under HAIP.
func TestHAIPDCAPIRejectsUnencryptedResponseMode(t *testing.T) {
	p := &Oid4vpPresenter{Profile: profile.HAIP}
	_, err := parseDCAPIForTest(p, dcapiUnsignedInvocation(t, "dc_api"))
	if err == nil {
		t.Fatal("HAIP must reject the unencrypted dc_api response mode")
	}
	if !strings.Contains(err.Error(), "HAIP requires the response_mode dc_api.jwt") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHAIPDCAPIAcceptsDCAPIJWT(t *testing.T) {
	p := &Oid4vpPresenter{Profile: profile.HAIP}
	request, err := parseDCAPIForTest(p, dcapiUnsignedInvocation(t, "dc_api.jwt"))
	if err != nil {
		t.Fatalf("HAIP must accept dc_api.jwt: %v", err)
	}
	if request.ResponseMode != OAuthAuthzReqResponseModeDCAPIJWT {
		t.Fatalf("response_mode = %q", request.ResponseMode)
	}
}

// OID4VP 1.0 Appendix A.2 keeps the unencrypted dc_api Response Mode available
// outside HAIP.
func TestFinalDCAPIStillAcceptsDCAPI(t *testing.T) {
	p := &Oid4vpPresenter{Profile: profile.Final}
	request, err := parseDCAPIForTest(p, dcapiUnsignedInvocation(t, "dc_api"))
	if err != nil {
		t.Fatalf("Final must accept dc_api: %v", err)
	}
	if request.ResponseMode != OAuthAuthzReqResponseModeDCAPI {
		t.Fatalf("response_mode = %q", request.ResponseMode)
	}
}

// finalQueryBuilderParams is a plain-query Final Authorization Request: legal
// under Final, and refused by HAIP §5.1, which requires a signed Request Object
// delivered by request_uri.
func finalQueryBuilderParams(responseType string) map[string][]string {
	return map[string][]string{
		"client_id":     {"redirect_uri:https://verifier.example/cb"},
		"redirect_uri":  {"https://verifier.example/cb"},
		"response_type": {responseType},
		"response_mode": {"fragment"},
		"nonce":         {"n"},
		"dcql_query":    {`{"credentials":[{"id":"cred","format":"dc+sd-jwt","meta":{"vct_values":["urn:test"]}}]}`},
	}
}

// The exported constructor must not produce a builder whose profile is the zero
// value, because every HAIP checkpoint would then be inert without saying so.
func TestNewRequestBuilderDefaultsToFinalProfile(t *testing.T) {
	b := NewRequestBuilder()
	if b.profile != profile.Final {
		t.Fatalf("profile = %q, want %q", b.profile, profile.Final)
	}
	// A HAIP-only rule (§5.1 delivery by request_uri) is not applied.
	if _, err := b.WithQueryParams(finalQueryBuilderParams("vp_token")).Build(); err != nil {
		t.Fatalf("Final must accept a plain query request: %v", err)
	}
	// A Final rule (§5.6 response_type vp_token) is applied.
	_, err := NewRequestBuilder().WithQueryParams(finalQueryBuilderParams("code")).Build()
	if err == nil || !strings.Contains(err.Error(), "response_type must be vp_token") {
		t.Fatalf("Final response_type rule not applied: %v", err)
	}
}

func TestRequestBuilderWithProfileEnforcesHAIP(t *testing.T) {
	b := NewRequestBuilder().WithProfile(profile.HAIP)
	if b.profile != profile.HAIP {
		t.Fatalf("profile = %q, want %q", b.profile, profile.HAIP)
	}
	_, err := b.WithQueryParams(finalQueryBuilderParams("vp_token")).Build()
	if err == nil || !strings.Contains(err.Error(), "request_uri") {
		t.Fatalf("WithProfile must apply HAIP: %v", err)
	}
}

func TestRequestBuilderWithProfileRejectsUnknownProfile(t *testing.T) {
	for _, unknown := range []profile.Profile{"HAIP", "draft24", "Final"} {
		_, err := NewRequestBuilder().WithProfile(unknown).WithQueryParams(finalQueryBuilderParams("vp_token")).Build()
		if err == nil || !strings.Contains(err.Error(), "unknown protocol profile") {
			t.Fatalf("WithProfile(%q): want unknown profile error, got %v", unknown, err)
		}
	}
}

// responseEncryptionFor returns the content encryption the wallet selected for
// an authorization response, as observed on the wire.
func responseEncryptionFor(t *testing.T, encValues []string, enc jose.ContentEncryption) {
	t.Helper()
	recipient := testutil.NewP256Key(t)
	s := newEncryptionServer(t)
	p := &Oid4vpPresenter{HTTPClient: s.server.Client()}
	request := &types.PresentationRequest{
		ResponseMode: string(OAuthAuthzReqResponseModeDirectPostJWT),
		ClientMetadata: &VerifierMetadata{
			Jwks: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
				Key: &recipient.PublicKey, KeyID: "enc-key", Use: "enc", Algorithm: "ECDH-ES",
			}}},
			EncryptedResponseEncValuesSupported: encValues,
		},
	}
	if _, err := sendDCQLForTest(p, s.endpoint(t), map[string][]string{"pid": {"credential"}}, request); err != nil {
		t.Fatal(err)
	}
	token := (<-s.forms).Get("response")
	if token == "" {
		t.Fatal("expected an encrypted response form field")
	}
	jwe, err := jose.ParseEncrypted(token, []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{enc})
	if err != nil {
		t.Fatalf("response is not encrypted with %s: %v", enc, err)
	}
	if got := jwe.Header.ExtraHeaders[jose.HeaderKey("enc")]; got != string(enc) {
		t.Fatalf("JWE enc = %#v, want %s", got, enc)
	}
}

// HAIP §5.1: "Wallets MUST support A128GCM or A256GCM, or both. If both are
// supported, the Wallet SHOULD use A256GCM." The verifier's list order must not
// decide it.
func TestResponseEncryptionPrefersA256GCMWhenOffered(t *testing.T) {
	responseEncryptionFor(t, []string{"A128GCM", "A256GCM"}, jose.A256GCM)
}

func TestResponseEncryptionFallsBackToA128GCMWhenOnlyOneOffered(t *testing.T) {
	responseEncryptionFor(t, []string{"A128GCM"}, jose.A128GCM)
}

// OID4VP 1.0 §8.3: an absent encrypted_response_enc_values_supported defaults
// to A128GCM.
func TestResponseEncryptionDefaultsToA128GCMWhenListAbsent(t *testing.T) {
	responseEncryptionFor(t, nil, jose.A128GCM)
}
