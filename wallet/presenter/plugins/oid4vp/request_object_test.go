package oid4vp

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	commonX509 "github.com/trustknots/vcknots/wallet/common/x509"
	"github.com/trustknots/vcknots/wallet/internal/httpfetch"
	"github.com/trustknots/vcknots/wallet/presenter/types"
	"github.com/trustknots/vcknots/wallet/profile"
)

func TestFinalRequestObjectAuthenticatesHashWithoutDNSAndChecksCRL(t *testing.T) {
	f := newRequestObjectFixture(t)
	claims := f.claims()
	claims["iss"] = map[string]any{"ignored": true}
	// client_metadata carries no key: X.509 authentication never reads it.
	// direct_post keeps the empty jwks admissible, since direct_post.jwt
	// would be refused for having nothing to encrypt the response to.
	claims["client_metadata"] = map[string]any{"jwks": map[string]any{"keys": []any{}}}
	claims["response_mode"] = "direct_post"
	req, err := f.parse(t, claims)
	if err != nil {
		t.Fatal(err)
	}
	proof := req.RequestObjectVerification
	if proof == nil || proof.ClientID != f.clientID() || len(proof.CertificateSHA256) != 2 || proof.RevocationChecked != 1 || proof.RevocationUnadvertised != 0 {
		t.Fatalf("missing authentication evidence: %+v", proof)
	}
	if len(f.leaf.DNSNames) != 0 {
		t.Fatal("fixture must have no DNS SAN")
	}
	f.setCRL(t, true)
	_, err = f.parse(t, claims)
	var crlErr *commonX509.CRLCheckError
	if !errors.As(err, &crlErr) || crlErr.Kind != commonX509.CRLErrorRevoked {
		t.Fatalf("revoked signer must be rejected on the next operation: %v", err)
	}
}

func TestFinalRequestObjectClaims(t *testing.T) {
	f := newRequestObjectFixture(t)
	tests := []struct {
		name string
		// wantError is the substring the rejection must name. An empty value
		// means the mutation must be accepted.
		wantError string
		mutate    func(map[string]any)
	}{
		{"optional dates absent", "", func(c map[string]any) { delete(c, "exp"); delete(c, "iat") }},
		{"expired", "request object is outside its exp validity", func(c map[string]any) { c["exp"] = f.now.Add(-time.Second).Unix() }},
		{"expiration boundary", "request object is outside its exp validity", func(c map[string]any) { c["exp"] = f.now.Unix() }},
		{"future nbf", "request object is outside its nbf validity", func(c map[string]any) { c["nbf"] = f.now.Add(time.Second).Unix() }},
		{"nbf boundary", "", func(c map[string]any) { c["nbf"] = f.now.Unix() }},
		{"fractional expiration", "", func(c map[string]any) { c["exp"] = float64(f.now.Unix()) + 0.5 }},
		{"fractional nbf", "request object is outside its nbf validity", func(c map[string]any) { c["nbf"] = float64(f.now.Unix()) + 0.5 }},
		{"future iat", "request object is issued in the future", func(c map[string]any) { c["iat"] = f.now.Add(time.Hour).Unix() }},
		{"iat boundary", "", func(c map[string]any) { c["iat"] = f.now.Unix() }},
		{"string exp", "exp must be a NumericDate", func(c map[string]any) { c["exp"] = "2000000000" }},
		{"null nbf", "nbf must be a NumericDate", func(c map[string]any) { c["nbf"] = nil }},
		{"string iat", "iat must be a NumericDate", func(c map[string]any) { c["iat"] = "yesterday" }},
		{"missing audience", "request object audience is required", func(c map[string]any) { delete(c, "aud") }},
		{"wrong audience", "request object audience does not identify this Wallet", func(c map[string]any) { c["aud"] = "another-wallet" }},
		{"audience array", "", func(c map[string]any) { c["aud"] = []string{"another-wallet", "https://self-issued.me/v2"} }},
		{"invalid audience array member", "invalid audience claim", func(c map[string]any) { c["aud"] = []any{1, "https://self-issued.me/v2"} }},
		{"outer client mismatch", "outer client_id does not match request object client_id", func(c map[string]any) { c["client_id"] = "x509_hash:another" }},
		{"nonstring nonce", "nonce must be a string", func(c map[string]any) { c["nonce"] = 42 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := f.claims()
			tt.mutate(claims)
			_, err := f.parse(t, claims)
			if tt.wantError == "" {
				if err != nil {
					t.Fatalf("want the request accepted, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("want error containing %q, got %v", tt.wantError, err)
			}
		})
	}
}

// TestFinalRequestObjectWithoutExpiryStillAccepted keeps the Final contract:
// OpenID4VP 1.0 states no exp rule for the Authorization Request Object, so
// only a caller or the HAIP profile may require one.
func TestFinalRequestObjectWithoutExpiryStillAccepted(t *testing.T) {
	f := newRequestObjectFixture(t)
	claims := f.claims()
	delete(claims, "exp")
	request, err := f.parse(t, claims)
	if err != nil {
		t.Fatalf("Final must accept a Request Object without exp: %v", err)
	}
	if request.RequestObjectVerification == nil {
		t.Fatal("accepted Request Object carries no authentication evidence")
	}
}

// TestHAIPRequestObjectRequiresExpiry covers the opt-in RequireExpiry policy:
// neither OpenID4VP 1.0 nor HAIP 1.0 requires exp on a Request Object (the
// official conformance verifiers sign without it), so a HAIP request without
// exp is accepted by default and rejected only when the caller opts in.
func TestHAIPRequestObjectRequiresExpiry(t *testing.T) {
	f := newRequestObjectFixture(t)
	claims := f.claims()
	delete(claims, "exp")
	if _, err := f.parseRequest(t, claims, requestFixtureOptions{Profile: profile.HAIP, Delivery: deliverByReference}); err != nil {
		t.Fatalf("HAIP must accept a Request Object without exp by default: %v", err)
	}
	_, err := f.parseRequest(t, claims, requestFixtureOptions{Profile: profile.HAIP, Delivery: deliverByReference, RequireExpiry: true})
	if err == nil || !strings.Contains(err.Error(), "request object is missing exp") {
		t.Fatalf("RequireExpiry must reject a Request Object without exp: %v", err)
	}
}

// TestHAIPRequestObjectRejectsExcessiveLifetime covers the ten-minute MaxAge
// the HAIP profile applies when the caller configured none.
func TestHAIPRequestObjectRejectsExcessiveLifetime(t *testing.T) {
	f := newRequestObjectFixture(t)
	claims := f.claims()
	claims["iat"] = f.now.Unix()
	claims["exp"] = f.now.Add(time.Hour).Unix()
	_, err := f.parseRequest(t, claims, requestFixtureOptions{Profile: profile.HAIP, Delivery: deliverByReference})
	if err == nil || !strings.Contains(err.Error(), "exceeding the configured maximum of 10m0s") {
		t.Fatalf("HAIP must bound the Request Object lifetime: %v", err)
	}
}

func TestHAIPRequestObjectAcceptsBoundedLifetime(t *testing.T) {
	f := newRequestObjectFixture(t)
	claims := f.claims()
	claims["iat"] = f.now.Unix()
	claims["exp"] = f.now.Add(5 * time.Minute).Unix()
	request, err := f.parseRequest(t, claims, requestFixtureOptions{Profile: profile.HAIP, Delivery: deliverByReference})
	if err != nil {
		t.Fatalf("HAIP must accept a bounded Request Object: %v", err)
	}
	if request.RequestObjectVerification == nil {
		t.Fatal("accepted Request Object carries no authentication evidence")
	}
}

// TestHAIPRequestObjectRejectsAnchorInX5CWithRootCAs covers HAIP Section 5:
// "The X.509 certificate of the trust anchor MUST NOT be included in the x5c
// JOSE header of the signed request." It holds when trust is configured as a
// *x509.CertPool instead of explicit TrustAnchors.
func TestHAIPRequestObjectRejectsAnchorInX5CWithRootCAs(t *testing.T) {
	f := newRequestObjectFixture(t)
	pool := x509.NewCertPool()
	pool.AddCert(f.root)
	options := RequestObjectValidationOptions{
		RootCAs: pool,
		Now:     func() time.Time { return f.now },
	}
	requestObject := f.signWithRoot(t, f.claims(), true)

	// The Request Object is passed by value; the attestation is what lets it
	// satisfy the HAIP Section 5.1 delivery requirement.
	haip := &Oid4vpPresenter{HTTPClient: f.server.Client(), RequestObjectValidation: &options, Profile: profile.HAIP}
	_, err := parseRequestObjectWithSourceForTest(haip, requestObject, types.RequestObjectSource{ClientID: f.clientID(), DeliveredByReference: true})
	if err == nil || !strings.Contains(err.Error(), "HAIP forbids including the trust anchor certificate in the x5c header") {
		t.Fatalf("HAIP must reject the anchor in x5c with a root pool: %v", err)
	}

	final := &Oid4vpPresenter{HTTPClient: f.server.Client(), RequestObjectValidation: &options}
	if _, err := parseRequestObjectForTest(final, requestObject, f.clientID()); err != nil {
		t.Fatalf("Final must still accept a chain that includes the anchor: %v", err)
	}
}

func TestFinalRequestObjectExplicitAudienceClockAndAlgorithms(t *testing.T) {
	f := newRequestObjectFixture(t)
	claims := f.claims()
	claims["aud"] = "https://wallet.example"
	claims["exp"] = f.now.Add(-time.Second).Unix()
	options := f.options()
	options.WalletAudience = []string{"https://wallet.example"}
	options.ClockSkew = 2 * time.Second
	p := f.presenter()
	p.RequestObjectValidation = &options
	uri := "openid4vp://authorize?" + url.Values{"client_id": []string{f.clientID()}, "request": []string{f.sign(t, claims, nil)}}.Encode()
	if _, err := p.ParsePresentationRequest(uri); err != nil {
		t.Fatal(err)
	}
	options.SigningAlgorithms = []jose.SignatureAlgorithm{jose.RS256}
	if _, err := p.ParsePresentationRequest(uri); err == nil {
		t.Fatal("algorithm outside caller allowlist was accepted")
	}
	options.SigningAlgorithms = nil
	options.ClockSkew = -time.Second
	if _, err := p.ParsePresentationRequest(uri); err == nil {
		t.Fatal("negative clock skew accepted")
	}
}

func TestFinalRequestObjectRejectsUntrustedOrUnprovenAuthentication(t *testing.T) {
	f := newRequestObjectFixture(t)
	claims := f.claims()
	uri := "openid4vp://authorize?" + url.Values{"client_id": []string{f.clientID()}, "request": []string{f.sign(t, claims, nil)}}.Encode()
	for _, insecure := range []bool{false, true} {
		p := &Oid4vpPresenter{HTTPClient: f.server.Client(), InsecureSkipX509Verify: insecure}
		if _, err := p.ParsePresentationRequest(uri); err == nil {
			t.Fatalf("untrusted leaf accepted with insecure=%v", insecure)
		}
	}
	other := newRequestObjectFixture(t)
	opts := other.options()
	p := f.presenter()
	p.RequestObjectValidation = &opts
	if _, err := p.ParsePresentationRequest(uri); err == nil {
		t.Fatal("unrelated root accepted")
	}
	for _, prefix := range []string{"x509_hash:any", "x509_san_dns:verifier.example"} {
		unsigned := "openid4vp://authorize?" + url.Values{
			"client_id": []string{prefix}, "response_type": []string{"vp_token"}, "response_mode": []string{"direct_post"},
			"response_uri": []string{f.server.URL + "/unexpected-post"}, "nonce": []string{"n"}, "dcql_query": []string{`{"credentials":[{"id":"q","format":"jwt_vc_json"}]}`},
		}.Encode()
		if _, err := f.presenter().ParsePresentationRequest(unsigned); err == nil {
			t.Fatal("unsigned X.509 client accepted")
		}
	}
	claims["client_id"] = "redirect_uri:https://verifier.example/response"
	claims["client_metadata"] = map[string]any{"jwks": jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &f.key.PublicKey, Algorithm: "ES256"}}}}
	token := f.sign(t, claims, (&jose.SignerOptions{}).WithType("oauth-authz-req+jwt"))
	uri = "openid4vp://authorize?" + url.Values{
		"client_id": []string{"redirect_uri:https://verifier.example/response"},
		"request":   []string{token},
	}.Encode()
	_, err := f.presenter().ParsePresentationRequest(uri)
	if err == nil || !strings.Contains(err.Error(), "no configured authentication method") {
		t.Fatalf("self-asserted metadata signing key accepted: %v", err)
	}
}

func TestFinalRequestObjectDNSBindingUsesResponseURIForBothPostModes(t *testing.T) {
	f := newRequestObjectFixture(t, "verifier.example")
	for _, mode := range []string{"direct_post", "direct_post.jwt", "fragment"} {
		t.Run(mode, func(t *testing.T) {
			claims := f.claims()
			claims["client_id"] = "x509_san_dns:verifier.example"
			claims["response_mode"] = mode
			bound := "response_uri"
			if mode == "fragment" {
				delete(claims, "response_uri")
				bound = "redirect_uri"
			}
			claims[bound] = "https://verifier.example/response"
			parse := func() error {
				uri := "openid4vp://authorize?" + url.Values{
					"client_id": []string{"x509_san_dns:verifier.example"},
					"request":   []string{f.sign(t, claims, nil)},
				}.Encode()
				_, err := f.presenter().ParsePresentationRequest(uri)
				return err
			}
			if err := parse(); err != nil {
				t.Fatal(err)
			}
			claims[bound] = "https://other.example/response"
			if err := parse(); err == nil {
				t.Fatal("endpoint host mismatch accepted")
			}
		})
	}
}

func TestFinalRequestObjectTypAndSignature(t *testing.T) {
	f := newRequestObjectFixture(t)
	for _, typ := range []string{"", "JWT", "oauth-authz-req+jwt"} {
		opts := (&jose.SignerOptions{}).WithHeader("x5c", []string{base64.StdEncoding.EncodeToString(f.leaf.Raw)})
		if typ != "" {
			opts.WithType(jose.ContentType(typ))
		}
		token := f.sign(t, f.claims(), opts)
		uri := "openid4vp://authorize?" + url.Values{"client_id": []string{f.clientID()}, "request": []string{token}}.Encode()
		_, err := f.presenter().ParsePresentationRequest(uri)
		if (err != nil) != (typ != "oauth-authz-req+jwt") {
			t.Fatalf("typ=%q err=%v", typ, err)
		}
	}
	token := f.sign(t, f.claims(), nil)
	parts := strings.Split(token, ".")
	tampered := f.claims()
	tampered["nonce"] = "changed-after-signing"
	raw, err := json.Marshal(tampered)
	if err != nil {
		t.Fatal(err)
	}
	parts[1] = base64.RawURLEncoding.EncodeToString(raw)
	tamperedURI := "openid4vp://authorize?" + url.Values{"client_id": []string{f.clientID()}, "request": []string{strings.Join(parts, ".")}}.Encode()
	if _, err := f.presenter().ParsePresentationRequest(tamperedURI); err == nil {
		t.Fatal("tampered Request Object accepted")
	}
}

func TestFinalRequestObjectByReference(t *testing.T) {
	f := newRequestObjectFixture(t)
	token := f.sign(t, f.claims(), nil)
	for _, method := range []string{"get", "post"} {
		t.Run(method, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.ToLower(r.Method) != method {
					t.Errorf("wrong request URI method: %s", r.Method)
				}
				body := token
				if method == "post" {
					// OID4VP 1.0 §5.10.1: the Request Object must echo the
					// wallet_nonce the Wallet sent in the POST body.
					if err := r.ParseForm(); err != nil {
						t.Errorf("failed to parse POST form: %v", err)
					}
					claims := f.claims()
					claims["wallet_nonce"] = r.Form.Get("wallet_nonce")
					body = f.sign(t, claims, nil)
				}
				w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
				_, _ = w.Write([]byte(body))
			}))
			defer server.Close()
			uri := "openid4vp://authorize?" + url.Values{
				"client_id": []string{f.clientID()}, "request_uri": []string{server.URL}, "request_uri_method": []string{method},
			}.Encode()
			req, err := f.presenter().ParsePresentationRequest(uri)
			if err != nil {
				t.Fatal(err)
			}
			if req.RequestObjectVerification == nil || req.RequestObjectVerification.RevocationChecked != 1 {
				t.Fatalf("request URI returned without authentication: %+v", req)
			}
		})
	}
}

func TestFinalRequestObjectRequiresOuterClientID(t *testing.T) {
	f := newRequestObjectFixture(t)
	uri := "openid4vp://authorize?request=" + url.QueryEscape(f.sign(t, f.claims(), nil))
	_, err := f.presenter().ParsePresentationRequest(uri)
	if err == nil || !strings.Contains(err.Error(), "client_id Authorization Request parameter is required with a Request Object") {
		t.Fatalf("missing outer client_id must be rejected: %v", err)
	}
}

func TestFinalRequestObjectRejectsOuterClientIDMismatch(t *testing.T) {
	f := newRequestObjectFixture(t)
	uri := "openid4vp://authorize?" + url.Values{
		"client_id": []string{"x509_hash:not-the-object-client-id"},
		"request":   []string{f.sign(t, f.claims(), nil)},
	}.Encode()
	_, err := f.presenter().ParsePresentationRequest(uri)
	if err == nil || !strings.Contains(err.Error(), "outer client_id does not match request object client_id") {
		t.Fatalf("mismatched outer client_id must be rejected: %v", err)
	}
}

func TestFinalRequestObjectDNSBindingIsCaseInsensitive(t *testing.T) {
	f := newRequestObjectFixture(t, "verifier.example.test")
	claims := f.claims()
	claims["client_id"] = "x509_san_dns:Verifier.Example.TEST"
	claims["response_mode"] = "direct_post"
	claims["response_uri"] = "https://VERIFIER.example.test/response"
	uri := "openid4vp://authorize?" + url.Values{
		"client_id": []string{"x509_san_dns:Verifier.Example.TEST"},
		"request":   []string{f.sign(t, claims, nil)},
	}.Encode()
	if _, err := f.presenter().ParsePresentationRequest(uri); err != nil {
		t.Fatalf("case-insensitive DNS binding rejected: %v", err)
	}
}

func TestFinalRequestObjectRejectsEmbeddedRequestParameters(t *testing.T) {
	f := newRequestObjectFixture(t)
	for _, key := range []string{"request", "request_uri"} {
		t.Run(key, func(t *testing.T) {
			claims := f.claims()
			claims[key] = "https://verifier.example/request"
			uri := "openid4vp://authorize?" + url.Values{
				"client_id": []string{f.clientID()},
				"request":   []string{f.sign(t, claims, nil)},
			}.Encode()
			_, err := f.presenter().ParsePresentationRequest(uri)
			if err == nil || !strings.Contains(err.Error(), "request object must not contain request or request_uri") {
				t.Fatalf("embedded %s must be rejected: %v", key, err)
			}
		})
	}
}

func TestFinalRequestObjectURIResponseIsBounded(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
		_, _ = w.Write(bytes.Repeat([]byte("a"), 1<<20+10))
	}))
	defer server.Close()
	f := newRequestObjectFixture(t)
	p := f.presenter()
	p.HTTPClient = server.Client()
	uri := "openid4vp://authorize?" + url.Values{
		"client_id":   []string{f.clientID()},
		"request_uri": []string{server.URL},
	}.Encode()
	_, err := p.ParsePresentationRequest(uri)
	if !errors.Is(err, httpfetch.ErrBodyTooLarge) {
		t.Fatalf("oversized request_uri response must be rejected: %v", err)
	}
}

// TestParsePresentationRequestRequestObjectSentinels drives every Request
// Object authentication sentinel through ParsePresentationRequest, so each is
// proven reachable with errors.Is from the innermost return rather than through
// a message-fragment classification.
func TestParsePresentationRequestRequestObjectSentinels(t *testing.T) {
	tests := []struct {
		name      string
		sentinel  error
		presenter func(*requestObjectFixture) *Oid4vpPresenter
		uri       func(*testing.T, *requestObjectFixture) string
	}{
		{
			name:     "typ invalid",
			sentinel: ErrRequestObjectTypInvalid,
			uri: func(t *testing.T, f *requestObjectFixture) string {
				options := (&jose.SignerOptions{}).
					WithType("JWT").
					WithHeader("x5c", []string{base64.StdEncoding.EncodeToString(f.leaf.Raw)})
				return signedRequestURI(f.clientID(), f.sign(t, f.claims(), options))
			},
		},
		{
			name:     "signature invalid",
			sentinel: ErrRequestObjectSignatureInvalid,
			uri: func(t *testing.T, f *requestObjectFixture) string {
				// Present f's certificate in x5c so the client_id binding
				// passes, but sign with another key so verification fails.
				other := newRequestObjectFixture(t)
				options := (&jose.SignerOptions{}).
					WithType("oauth-authz-req+jwt").
					WithHeader("x5c", []string{base64.StdEncoding.EncodeToString(f.leaf.Raw)})
				signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: other.key}, options)
				if err != nil {
					t.Fatal(err)
				}
				token, err := jwt.Signed(signer).Claims(f.claims()).Serialize()
				if err != nil {
					t.Fatal(err)
				}
				return signedRequestURI(f.clientID(), token)
			},
		},
		{
			name:     "audience mismatch",
			sentinel: ErrRequestObjectAudienceMismatch,
			uri: func(t *testing.T, f *requestObjectFixture) string {
				claims := f.claims()
				claims["aud"] = "another-wallet"
				return signedRequestURI(f.clientID(), f.sign(t, claims, nil))
			},
		},
		{
			name:     "expired",
			sentinel: ErrRequestObjectExpired,
			uri: func(t *testing.T, f *requestObjectFixture) string {
				claims := f.claims()
				claims["exp"] = f.now.Add(-time.Second).Unix()
				return signedRequestURI(f.clientID(), f.sign(t, claims, nil))
			},
		},
		{
			name:     "outer client_id mismatch",
			sentinel: ErrRequestObjectClientIDMismatch,
			uri: func(t *testing.T, f *requestObjectFixture) string {
				return signedRequestURI("x509_hash:not-the-object-client-id", f.sign(t, f.claims(), nil))
			},
		},
		{
			name:     "x509_hash mismatch",
			sentinel: ErrX509HashMismatch,
			uri: func(t *testing.T, f *requestObjectFixture) string {
				wrong := "x509_hash:" + base64.RawURLEncoding.EncodeToString([]byte("wrong-leaf-hash"))
				claims := f.claims()
				claims["client_id"] = wrong
				return signedRequestURI(wrong, f.sign(t, claims, nil))
			},
		},
		{
			name:     "haip request_uri required",
			sentinel: ErrHAIPRequestURIRequired,
			presenter: func(f *requestObjectFixture) *Oid4vpPresenter {
				return f.presenterWith(requestFixtureOptions{Profile: profile.HAIP, Delivery: deliverByValue})
			},
			uri: func(t *testing.T, f *requestObjectFixture) string {
				return signedRequestURI(f.clientID(), f.sign(t, f.claims(), nil))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newRequestObjectFixture(t)
			presenter := f.presenter()
			if tt.presenter != nil {
				presenter = tt.presenter(f)
			}
			_, err := presenter.ParsePresentationRequest(tt.uri(t, f))
			if !errors.Is(err, tt.sentinel) {
				t.Fatalf("ParsePresentationRequest did not return %v: %v", tt.sentinel, err)
			}
		})
	}
}

// signedRequestURI assembles the by-value Authorization Request a Final
// Request Object arrives in.
func signedRequestURI(clientID, token string) string {
	return "openid4vp://authorize?" + url.Values{
		"client_id": {clientID},
		"request":   {token},
	}.Encode()
}

// A Wallet that shows or stores how long the Verifier's request stays valid
// must read exp from the library's own authentication record, not by decoding
// the Request Object a second time.
func TestRequestObjectVerificationReportsExpiry(t *testing.T) {
	for _, tc := range []struct {
		name   string
		claims map[string]any
		want   int64
	}{
		{name: "integer exp", claims: map[string]any{"exp": json.Number("1700000000")}, want: 1700000000},
		{name: "fractional exp", claims: map[string]any{"exp": json.Number("1700000000.5")}, want: 1700000000},
		{name: "absent exp", claims: map[string]any{}},
		{name: "unusable exp", claims: map[string]any{"exp": "soon"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expiry := requestObjectExpiry(tc.claims)
			if tc.want == 0 {
				if !expiry.IsZero() {
					t.Fatalf("expiry = %v, want zero", expiry)
				}
				return
			}
			if expiry.Unix() != tc.want {
				t.Fatalf("expiry = %d, want %d", expiry.Unix(), tc.want)
			}
			if expiry.Location() != time.UTC {
				t.Fatalf("expiry location = %v, want UTC", expiry.Location())
			}
		})
	}
}

// A Final Request Object issued in the future is refused, so a lifetime bound
// measured as exp - iat cannot be bypassed by moving iat forward.
func TestFinalRequestObjectIssuedInTheFuture(t *testing.T) {
	f := newRequestObjectFixture(t)
	claims := f.claims()
	claims["iat"] = f.now.Add(time.Hour).Unix()
	claims["exp"] = f.now.Add(time.Hour + 5*time.Minute).Unix()
	_, err := f.parseRequest(t, claims, requestFixtureOptions{Profile: profile.HAIP, Delivery: deliverByReference})
	if !errors.Is(err, ErrRequestObjectExpired) {
		t.Fatalf("want ErrRequestObjectExpired for a future iat, got %v", err)
	}

	claims = f.claims()
	claims["iat"] = f.now.Add(30 * time.Second).Unix()
	options := requestFixtureOptions{Delivery: deliverByReference}
	presenter := f.presenterWith(options)
	presenter.RequestObjectValidation.ClockSkew = time.Minute
	f.mu.Lock()
	f.requestObject = []byte(f.signWithRoot(t, claims, false))
	f.mu.Unlock()
	uri := "openid4vp://authorize?" + url.Values{"client_id": {f.clientID()}, "request_uri": {f.server.URL + "/request-object"}}.Encode()
	if _, err := presenter.ParsePresentationRequest(uri); err != nil {
		t.Fatalf("an iat within the clock skew must be accepted: %v", err)
	}
}
