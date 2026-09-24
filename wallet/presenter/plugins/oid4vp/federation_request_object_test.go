package oid4vp

import (
	"crypto/ecdsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/trustknots/vcknots/wallet/internal/testutil"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp/federation"
)

const federationResponseURI = "https://verifier.example/response"

// federationRequestFixture is a Verifier directly below a Trust Anchor, both
// published as Entity Identifiers on one TLS server, and the Request Objects
// that Verifier signs.
type federationRequestFixture struct {
	server               *httptest.Server
	mu                   sync.Mutex
	statements           map[string]string
	now                  time.Time
	verifierID, anchorID string
	verifierKey          *ecdsa.PrivateKey
	anchorKey            *ecdsa.PrivateKey
	chain                []string
}

const (
	federationVerifierKid = "verifier-key"
	federationAnchorKid   = "anchor-key"
)

func newFederationRequestFixture(t *testing.T) *federationRequestFixture {
	t.Helper()
	f := &federationRequestFixture{
		statements:  map[string]string{},
		now:         time.Now().UTC().Truncate(time.Second),
		verifierKey: testutil.NewP256Key(t),
		anchorKey:   testutil.NewP256Key(t),
	}
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		statement, ok := f.statements["https://"+r.Host+r.URL.RequestURI()]
		f.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/entity-statement+jwt")
		_, _ = w.Write([]byte(statement))
	}))
	t.Cleanup(f.server.Close)
	f.verifierID, f.anchorID = f.server.URL+"/verifier", f.server.URL+"/anchor"
	fetchEndpoint := f.anchorID + "/fetch"

	iat, exp := f.now.Add(-time.Minute).Unix(), f.now.Add(10*time.Minute).Unix()
	configuration := signEntityStatement(t, f.verifierKey, federationVerifierKid, map[string]any{
		"iss": f.verifierID, "sub": f.verifierID, "iat": iat, "exp": exp,
		"jwks": publicJWKS(f.verifierKey, federationVerifierKid), "authority_hints": []string{f.anchorID},
		"metadata": map[string]any{
			"openid_credential_verifier": map[string]any{
				"client_name":          "Federated verifier",
				"redirect_uris":        []string{federationResponseURI},
				"vp_formats_supported": map[string]any{"dc+sd-jwt": map[string]any{"sd-jwt_alg_values": []string{"ES256"}}},
			},
			"federation_entity": map[string]any{
				"organization_name": "Example Verifier",
				"logo_uri":          "https://verifier.example/logo.png",
				"policy_uri":        "https://verifier.example/policy",
				"organization_uri":  "https://verifier.example/",
			},
		},
	})
	subordinate := signEntityStatement(t, f.anchorKey, federationAnchorKid, map[string]any{
		"iss": f.anchorID, "sub": f.verifierID, "iat": iat, "exp": exp - 60,
		"jwks": publicJWKS(f.verifierKey, federationVerifierKid),
	})
	anchor := signEntityStatement(t, f.anchorKey, federationAnchorKid, map[string]any{
		"iss": f.anchorID, "sub": f.anchorID, "iat": iat, "exp": exp,
		"jwks":     publicJWKS(f.anchorKey, federationAnchorKid),
		"metadata": map[string]any{"federation_entity": map[string]any{"federation_fetch_endpoint": fetchEndpoint}},
	})
	configurationURL, _ := federation.EntityConfigurationURL(f.verifierID)
	anchorURL, _ := federation.EntityConfigurationURL(f.anchorID)
	subordinateURL, _ := federation.SubordinateStatementURL(fetchEndpoint, f.verifierID)
	f.statements[configurationURL] = configuration
	f.statements[anchorURL] = anchor
	f.statements[subordinateURL] = subordinate
	f.chain = []string{configuration, subordinate, anchor}
	return f
}

func publicJWKS(key *ecdsa.PrivateKey, kid string) jose.JSONWebKeySet {
	return jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: kid, Algorithm: string(jose.ES256), Use: "sig"}}}
}

func signEntityStatement(t *testing.T, key *ecdsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	return signJWT(t, jose.ES256, jose.JSONWebKey{Key: key, KeyID: kid}, (&jose.SignerOptions{}).WithType("entity-statement+jwt"), claims)
}

func signJWT(t *testing.T, alg jose.SignatureAlgorithm, key any, options *jose.SignerOptions, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, options)
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func (f *federationRequestFixture) clientID() string { return "openid_federation:" + f.verifierID }

func (f *federationRequestFixture) claims() map[string]any {
	return map[string]any{
		"iat": f.now.Unix(), "exp": f.now.Add(5 * time.Minute).Unix(),
		"aud": "https://self-issued.me/v2", "client_id": f.clientID(),
		"nonce": "nonce", "response_type": "vp_token", "response_mode": "direct_post",
		"response_uri": federationResponseURI,
		// OpenID4VP 1.0 Section 5.9.3: client_metadata "MUST be ignored" for
		// this prefix; the chain's metadata replaces it.
		"client_metadata": map[string]any{"client_name": "Self-asserted name"},
		"dcql_query": map[string]any{"credentials": []any{map[string]any{
			"id": "pid", "format": "dc+sd-jwt", "meta": map[string]any{"vct_values": []string{"urn:eudi:pid:1"}},
		}}},
	}
}

// requestObject signs claims as the Verifier, with its kid unless kid is
// overridden, and extra protected headers.
func (f *federationRequestFixture) requestObject(t *testing.T, claims map[string]any, key *ecdsa.PrivateKey, kid string, headers map[jose.HeaderKey]any) string {
	t.Helper()
	options := (&jose.SignerOptions{}).WithType("oauth-authz-req+jwt")
	for name, value := range headers {
		options = options.WithHeader(name, value)
	}
	var signingKey any = key
	if kid != "" {
		signingKey = jose.JSONWebKey{Key: key, KeyID: kid}
	}
	return signJWT(t, jose.ES256, signingKey, options, claims)
}

func (f *federationRequestFixture) options() RequestObjectValidationOptions {
	return RequestObjectValidationOptions{
		Now: func() time.Time { return f.now },
		Federation: &FederationTrustOptions{
			TrustAnchors:     []federation.TrustAnchor{{EntityID: f.anchorID, JWKS: publicJWKS(f.anchorKey, federationAnchorKid)}},
			PreferredLocales: []string{"en"},
		},
	}
}

func (f *federationRequestFixture) parse(t *testing.T, requestObject string, options RequestObjectValidationOptions, client *http.Client) (*CredentialPresentationRequest, error) {
	t.Helper()
	presenter := &Oid4vpPresenter{HTTPClient: client, RequestObjectValidation: &options}
	return parseRequestObjectForTest(presenter, requestObject, f.clientID())
}

func TestFederationRequestObjectWithDiscoveredTrustChain(t *testing.T) {
	f := newFederationRequestFixture(t)
	request, err := f.parse(t, f.requestObject(t, f.claims(), f.verifierKey, federationVerifierKid, nil), f.options(), f.server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if request.ClientMetadata == nil || request.ClientMetadata.ClientName != "Federated verifier" ||
		!reflect.DeepEqual(request.ClientMetadata.RedirectURIs, []string{federationResponseURI}) {
		t.Fatalf("client_metadata was not replaced by the chain metadata: %+v", request.ClientMetadata)
	}
	verification := request.RequestObjectVerification
	if verification == nil || verification.Federation == nil || verification.ClientID != f.clientID() {
		t.Fatalf("missing federation evidence: %+v", verification)
	}
	evidence := verification.Federation
	if evidence.SubjectEntityID != f.verifierID || evidence.TrustAnchorEntityID != f.anchorID ||
		!reflect.DeepEqual(evidence.TrustPathEntityIDs, []string{f.verifierID, f.anchorID}) || evidence.StatementCount != 3 {
		t.Fatalf("unexpected trust path evidence: %+v", evidence)
	}
	if want := f.now.Add(9 * time.Minute); !evidence.ExpiresAt.Equal(want) || evidence.ExpiresAt.Location() != time.UTC {
		t.Fatalf("expiresAt = %v, want the earliest statement exp %v in UTC", evidence.ExpiresAt, want)
	}
	if evidence.OrganizationName != "Example Verifier" || evidence.LogoURI != "https://verifier.example/logo.png" ||
		evidence.PolicyURI != "https://verifier.example/policy" || evidence.HomepageURI != "https://verifier.example/" {
		t.Fatalf("unexpected display evidence: %+v", evidence)
	}
	if evidence.Metadata["vp_formats"] == nil || evidence.Metadata["client_name"] != "Federated verifier" {
		t.Fatalf("unexpected verifier metadata: %v", evidence.Metadata)
	}
	if !verification.ExpiresAt.Equal(f.now.Add(5 * time.Minute)) {
		t.Fatalf("request object expiry = %v", verification.ExpiresAt)
	}
}

// offlineClient fails the test on any network request, so a carried Trust
// Chain is proven to need no discovery.
func offlineClient(t *testing.T) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Error("a carried trust chain must not be discovered")
		return nil, errors.New("offline")
	})}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestFederationRequestObjectWithCarriedTrustChain(t *testing.T) {
	f := newFederationRequestFixture(t)
	t.Run("trust_chain JOSE header", func(t *testing.T) {
		requestObject := f.requestObject(t, f.claims(), f.verifierKey, federationVerifierKid, map[jose.HeaderKey]any{"trust_chain": f.chain})
		request, err := f.parse(t, requestObject, f.options(), offlineClient(t))
		if err != nil {
			t.Fatal(err)
		}
		if request.RequestObjectVerification.Federation.TrustAnchorEntityID != f.anchorID {
			t.Fatalf("unexpected evidence: %+v", request.RequestObjectVerification.Federation)
		}
	})
	t.Run("trust_chain claim", func(t *testing.T) {
		claims := f.claims()
		claims["trust_chain"] = f.chain
		if _, err := f.parse(t, f.requestObject(t, claims, f.verifierKey, federationVerifierKid, nil), f.options(), offlineClient(t)); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("anchor configured with other keys", func(t *testing.T) {
		options := f.options()
		options.Federation.TrustAnchors[0].JWKS = publicJWKS(testutil.NewP256Key(t), federationAnchorKid)
		requestObject := f.requestObject(t, f.claims(), f.verifierKey, federationVerifierKid, map[jose.HeaderKey]any{"trust_chain": f.chain})
		_, err := f.parse(t, requestObject, options, offlineClient(t))
		requireErrorIs(t, err, federation.ErrTrustChainInvalid)
	})
	t.Run("malformed trust_chain header", func(t *testing.T) {
		requestObject := f.requestObject(t, f.claims(), f.verifierKey, federationVerifierKid, map[jose.HeaderKey]any{"trust_chain": []any{""}})
		_, err := f.parse(t, requestObject, f.options(), offlineClient(t))
		requireErrorIs(t, err, federation.ErrTrustChainInvalid)
	})
}

func TestFederationRequestObjectRefusals(t *testing.T) {
	f := newFederationRequestFixture(t)
	stranger := testutil.NewP256Key(t)
	cases := []struct {
		name    string
		request func() string
		options func() RequestObjectValidationOptions
		want    error
	}{
		{
			name:    "missing kid",
			request: func() string { return f.requestObject(t, f.claims(), f.verifierKey, "", nil) },
			want:    ErrRequestObjectSignatureInvalid,
		},
		{
			name:    "alg outside the federation policy",
			request: func() string { return f.requestObject(t, f.claims(), f.verifierKey, federationVerifierKid, nil) },
			options: func() RequestObjectValidationOptions {
				options := f.options()
				options.Federation.SigningAlgorithms = []jose.SignatureAlgorithm{jose.ES384}
				return options
			},
			want: ErrRequestObjectSignatureInvalid,
		},
		{
			name:    "signed by a key the subject did not publish",
			request: func() string { return f.requestObject(t, f.claims(), stranger, federationVerifierKid, nil) },
			want:    ErrRequestObjectSignatureInvalid,
		},
		{
			name: "response_uri outside redirect_uris",
			request: func() string {
				claims := f.claims()
				claims["response_uri"] = "https://attacker.example/response"
				return f.requestObject(t, claims, f.verifierKey, federationVerifierKid, nil)
			},
			want: federation.ErrResponseURINotRegistered,
		},
		{
			name:    "no federation options",
			request: func() string { return f.requestObject(t, f.claims(), f.verifierKey, federationVerifierKid, nil) },
			options: func() RequestObjectValidationOptions {
				return RequestObjectValidationOptions{Now: func() time.Time { return f.now }}
			},
			want: federation.ErrTrustAnchorNotConfigured,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			options := f.options()
			if tc.options != nil {
				options = tc.options()
			}
			request, err := f.parse(t, tc.request(), options, f.server.Client())
			if request != nil {
				t.Fatalf("a refused request was returned: %+v", request)
			}
			requireErrorIs(t, err, tc.want)
		})
	}
}

func requireErrorIs(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("expected %v, got %v", want, err)
	}
}

// An unsigned openid_federation request authenticates nothing about the
// request itself, so it is refused before any Trust Chain is resolved unless
// the Wallet opts in with AllowUnsignedRequests.
func TestFederationUnsignedRequestNeedsOptIn(t *testing.T) {
	f := newFederationRequestFixture(t)
	query := url.Values{
		"client_id": {f.clientID()}, "response_type": {"vp_token"}, "response_mode": {"direct_post"},
		"response_uri": {federationResponseURI}, "nonce": {"n"},
		"dcql_query": {`{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]}}]}`},
	}
	uri := "openid4vp://authorize?" + query.Encode()

	options := f.options()
	refusing := &Oid4vpPresenter{HTTPClient: offlineClient(t), RequestObjectValidation: &options}
	if _, err := refusing.ParsePresentationRequest(uri); !errors.Is(err, ErrRequestObjectSignatureRequired) {
		t.Fatalf("want ErrRequestObjectSignatureRequired, got %v", err)
	}

	allowing := f.options()
	allowing.Federation.AllowUnsignedRequests = true
	presenter := &Oid4vpPresenter{HTTPClient: f.server.Client(), RequestObjectValidation: &allowing}
	request, err := presenter.ParsePresentationRequest(uri)
	if err != nil {
		t.Fatal(err)
	}
	if request.VerifierFederation == nil || request.VerifierFederation.SubjectEntityID != f.verifierID {
		t.Fatalf("missing federation evidence: %+v", request.VerifierFederation)
	}
}

// The default Request Object algorithm policy is returned as a copy, so a
// caller cannot widen it for every presenter in the process.
func TestDefaultFederationRequestObjectAlgorithmsIsACopy(t *testing.T) {
	algorithms := DefaultFederationRequestObjectAlgorithms()
	algorithms[0] = jose.RS256
	if got := DefaultFederationRequestObjectAlgorithms(); !reflect.DeepEqual(got, []jose.SignatureAlgorithm{jose.ES256}) {
		t.Fatalf("DefaultFederationRequestObjectAlgorithms() = %v after a caller changed its copy", got)
	}
}
