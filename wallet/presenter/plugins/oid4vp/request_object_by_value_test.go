package oid4vp

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/trustknots/vcknots/wallet/presenter/types"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/trustknots/vcknots/wallet/profile"
)

// TestParseRequestObjectMatchesTheURIDelivery is the contract of the by-value
// entry point: the same signed Request Object authenticated with
// ParseRequestObject and with the request= Authorization Request parameter
// yields the same CredentialPresentationRequest, including the authentication
// evidence, because both run the same builder.
func TestParseRequestObjectMatchesTheURIDelivery(t *testing.T) {
	f := newRequestObjectFixture(t)
	requestObject := f.sign(t, f.claims(), nil)

	uri := "openid4vp://authorize?" + url.Values{
		"client_id": {f.clientID()},
		"request":   {requestObject},
	}.Encode()
	fromURI, err := f.presenter().ParsePresentationRequest(uri)
	if err != nil {
		t.Fatalf("the URI delivery must be accepted: %v", err)
	}
	fromValue, err := parseRequestObjectForTest(f.presenter(), requestObject, f.clientID())
	if err != nil {
		t.Fatalf("the by-value delivery must be accepted: %v", err)
	}
	if !reflect.DeepEqual(fromURI, fromValue) {
		t.Fatalf("by-value and by-URI results differ:\n%+v\n%+v", fromValue, fromURI)
	}
	if fromValue.RequestObjectVerification == nil ||
		fromValue.RequestObjectVerification.Delivery != "value" ||
		fromValue.RequestObjectVerification.ClientID != f.clientID() {
		t.Fatalf("missing authentication evidence: %+v", fromValue.RequestObjectVerification)
	}
}

// TestParseDraft24RequestObjectMatchesTheURIDelivery repeats the parity check
// for the Presentation Exchange wire contract, whose by-value entry point
// authenticates an X.509 Request Object through the same shared path.
func TestParseDraft24RequestObjectMatchesTheURIDelivery(t *testing.T) {
	f := newRequestObjectFixture(t)
	claims := f.claims()
	claims["response_mode"] = "direct_post"
	delete(claims, "dcql_query")
	claims["presentation_definition"] = map[string]any{"id": "pid-definition"}
	requestObject := f.sign(t, claims, nil)

	uri := "openid4vp://authorize?" + url.Values{
		"client_id": {f.clientID()},
		"request":   {requestObject},
	}.Encode()
	fromURI, err := parseDraft24ForTest(f.presenter(), uri)
	if err != nil {
		t.Fatalf("the Draft24 URI delivery must be accepted: %v", err)
	}
	fromValue, err := parseDraft24RequestObjectForTest(f.presenter(), requestObject, f.clientID())
	if err != nil {
		t.Fatalf("the Draft24 by-value delivery must be accepted: %v", err)
	}
	if !reflect.DeepEqual(fromURI, fromValue) {
		t.Fatalf("by-value and by-URI Draft24 results differ:\n%+v\n%+v", fromValue, fromURI)
	}
}

// TestParseRequestObjectRejectsClientIDMismatch keeps the OpenID4VP 1.0
// Section 5.10.1 cross-check available to a caller that holds the
// Authorization Request client_id, with the typed error the URI path returns.
func TestParseRequestObjectRejectsClientIDMismatch(t *testing.T) {
	f := newRequestObjectFixture(t)
	requestObject := f.sign(t, f.claims(), nil)

	_, err := parseRequestObjectForTest(f.presenter(), requestObject, "x509_hash:another")
	if !errors.Is(err, ErrRequestObjectClientIDMismatch) {
		t.Fatalf("want ErrRequestObjectClientIDMismatch, got %v", err)
	}
	if _, err := parseRequestObjectForTest(f.presenter(), requestObject, "not a client identifier:"); err == nil ||
		!strings.Contains(err.Error(), "invalid client_id in initial request") {
		t.Fatalf("want a malformed client_id refused before authentication, got %v", err)
	}
}

// TestParseRequestObjectWithoutExpectedClientID covers the caller that holds
// the Request Object alone: there is no outer parameter to compare against, so
// the comparison is skipped, but the client_id claim is still bound to the
// certificate that signed the Request Object.
func TestParseRequestObjectWithoutExpectedClientID(t *testing.T) {
	f := newRequestObjectFixture(t)
	request, err := parseRequestObjectForTest(f.presenter(), f.sign(t, f.claims(), nil), "")
	if err != nil {
		t.Fatalf("a Request Object without an outer client_id must be accepted: %v", err)
	}
	if request.RequestObjectVerification == nil || request.ClientID != f.clientID() {
		t.Fatalf("the client_id must stay bound to the signing certificate: %+v", request.RequestObjectVerification)
	}

	other := newRequestObjectFixture(t)
	claims := f.claims()
	claims["client_id"] = other.clientID()
	if _, err := parseRequestObjectForTest(f.presenter(), f.sign(t, claims, nil), ""); !errors.Is(err, ErrX509HashMismatch) {
		t.Fatalf("want ErrX509HashMismatch for a client_id the signer cannot speak for, got %v", err)
	}
}

// TestParseRequestObjectRefusesUnsignedRequests keeps the by-value entry point
// a Request Object entry point: the Final profile authenticates the request
// through its signature, so an alg=none JWT and a bare parameter document are
// both refused instead of being read as Authorization Request parameters.
func TestParseRequestObjectRefusesUnsignedRequests(t *testing.T) {
	f := newRequestObjectFixture(t)
	claims := f.claims()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	header, err := json.Marshal(map[string]any{"alg": "none", "typ": "oauth-authz-req+jwt"})
	if err != nil {
		t.Fatal(err)
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload) + "."

	if _, err := parseRequestObjectForTest(f.presenter(), unsigned, f.clientID()); !errors.Is(err, ErrRequestObjectSignatureInvalid) {
		t.Fatalf("want ErrRequestObjectSignatureInvalid for an alg=none request object, got %v", err)
	}
	if _, err := parseRequestObjectForTest(f.presenter(), string(payload), f.clientID()); err == nil ||
		!strings.Contains(err.Error(), "bounded compact signed JWT") {
		t.Fatalf("want a non-JWT request refused, got %v", err)
	}
	if _, err := parseDraft24RequestObjectForTest(f.presenter(), unsigned, f.clientID()); !errors.Is(err, ErrRequestObjectSignatureInvalid) {
		t.Fatalf("want the Draft24 entry point to refuse an alg=none request object, got %v", err)
	}
}

// TestParseRequestObjectHAIPDeliveryPolicy keeps the HAIP Section 5.1 delivery
// rule on the by-value entry point: a Request Object the library did not fetch
// through request_uri is refused unless the caller attests the fetch with
// RequestObjectSource.DeliveredByReference.
func TestParseRequestObjectHAIPDeliveryPolicy(t *testing.T) {
	f := newRequestObjectFixture(t)
	requestObject := f.sign(t, f.claims(), nil)

	if _, err := parseRequestObjectForTest(f.haipPresenter(), requestObject, f.clientID()); !errors.Is(err, ErrHAIPRequestURIRequired) {
		t.Fatalf("want ErrHAIPRequestURIRequired without a delivery attestation, got %v", err)
	}
	request, err := parseRequestObjectWithSourceForTest(f.haipPresenter(), requestObject, types.RequestObjectSource{ClientID: f.clientID(), DeliveredByReference: true})
	if err != nil {
		t.Fatalf("an attested delivery must be accepted under HAIP: %v", err)
	}
	if proof := request.RequestObjectVerification; proof == nil || !proof.DeliveryAttested || proof.Delivery != "value" {
		t.Fatalf("the attested delivery must be recorded: %+v", proof)
	}
}

// TestParseRequestObjectIsNotTheDCAPIEntryPoint records what a by-value caller
// cannot supply here: a Digital Credentials API invocation carries a
// platform-authenticated Origin and is parsed by ParseDCAPIRequest, so a DC API
// Response Mode reaching this entry point is refused the same way it is when it
// arrives as an Authorization Request parameter.
func TestParseRequestObjectIsNotTheDCAPIEntryPoint(t *testing.T) {
	f := newRequestObjectFixture(t)
	claims := f.claims()
	claims["response_mode"] = "dc_api.jwt"
	delete(claims, "response_uri")
	requestObject := f.sign(t, claims, nil)

	_, valueErr := parseRequestObjectWithSourceForTest(f.haipPresenter(), requestObject, types.RequestObjectSource{ClientID: f.clientID(), DeliveredByReference: true})
	if valueErr == nil || !strings.Contains(valueErr.Error(), "only valid over the Digital Credentials API") {
		t.Fatalf("want a DC API response mode refused by value, got %v", valueErr)
	}
	uri := "openid4vp://authorize?" + url.Values{
		"client_id": {f.clientID()},
		"request":   {requestObject},
	}.Encode()
	_, uriErr := f.haipPresenter().ParsePresentationRequest(uri)
	if uriErr == nil || uriErr.Error() != valueErr.Error() {
		t.Fatalf("the two deliveries must refuse a DC API response mode alike: %v vs %v", valueErr, uriErr)
	}
}

// haipPresenter builds a HAIP presenter that trusts the fixture root.
func (f *requestObjectFixture) haipPresenter() *Oid4vpPresenter {
	validation := RequestObjectValidationOptions{
		TrustAnchors: []*x509.Certificate{f.root},
		Now:          func() time.Time { return f.now },
	}
	return &Oid4vpPresenter{
		HTTPClient:              f.server.Client(),
		RequestObjectValidation: &validation,
		Profile:                 profile.HAIP,
	}
}

// TestParseRequestObjectAttestsCallerWalletNonce: an application that fetched
// the Request Object with its own request_uri POST names the wallet_nonce it
// sent (RequestObjectSource.WalletNonce), and the by-value entry
// point holds the Request Object to it exactly as it would hold one this
// library fetched (OpenID4VP 1.0 Section 5.10.1).
func TestParseRequestObjectAttestsCallerWalletNonce(t *testing.T) {
	const sent = "caller-wallet-nonce"
	cases := []struct {
		name        string
		walletNonce string
		claim       any
		wantErr     bool
	}{
		{name: "echoed", walletNonce: sent, claim: sent},
		{name: "different", walletNonce: sent, claim: "other-nonce", wantErr: true},
		{name: "missing", walletNonce: sent, wantErr: true},
		{name: "not a string", walletNonce: sent, claim: 42, wantErr: true},
		{name: "no nonce attested ignores the claim", claim: "unsolicited"},
	}
	for _, draft24 := range []bool{false, true} {
		for _, tc := range cases {
			name := tc.name
			if draft24 {
				name = "draft24/" + name
			}
			t.Run(name, func(t *testing.T) {
				f := newRequestObjectFixture(t)
				claims := f.claims()
				if tc.claim != nil {
					claims["wallet_nonce"] = tc.claim
				}
				p := f.presenter()
				parse := p.ParseRequestObject
				if draft24 {
					claims["response_mode"] = "direct_post"
					delete(claims, "dcql_query")
					claims["presentation_definition"] = map[string]any{"id": "pid-definition"}
					parse = p.ParseDraft24RequestObject
				}
				request, err := admittedRequest(parse(context.Background(), f.sign(t, claims, nil), types.RequestObjectSource{ClientID: f.clientID(), WalletNonce: tc.walletNonce}))
				if tc.wantErr {
					if !errors.Is(err, ErrRequestObjectWalletNonceMismatch) {
						t.Fatalf("want ErrRequestObjectWalletNonceMismatch, got %v", err)
					}
					return
				}
				if err != nil {
					t.Fatalf("want the Request Object accepted, got %v", err)
				}
				if got := request.RequestObjectVerification.WalletNonce; got != tc.walletNonce {
					t.Fatalf("RequestObjectVerification.WalletNonce = %q, want %q", got, tc.walletNonce)
				}
			})
		}
	}
}
