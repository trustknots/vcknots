package oid4vp

import (
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

// draft24RedirectURIValues is a Draft24 direct_post request from a
// redirect_uri Client Identifier.
func draft24RedirectURIValues(clientURI, responseURI string) url.Values {
	return url.Values{
		"client_id":               {"redirect_uri:" + clientURI},
		"response_type":           {"vp_token"},
		"response_mode":           {"direct_post"},
		"response_uri":            {responseURI},
		"nonce":                   {"n"},
		"presentation_definition": {`{"id":"definition"}`},
	}
}

// Draft24 Section 5.10.1: with the redirect_uri scheme the Client Identifier
// "is the Redirect URI (or Response URI when Response Mode direct_post is
// used)", so the Response URI is bound to it exactly as on the Final path. The
// pre-Draft22 tolerance admits a callback under the Client Identifier's path
// only while the request still carries client_id_scheme=redirect_uri.
func TestDraft24RedirectURIClientIDBindsResponseURI(t *testing.T) {
	tests := []struct {
		name         string
		clientURI    string
		responseURI  string
		scheme       string
		allowHTTP    bool
		wantAccepted bool
	}{
		{name: "same URI", clientURI: "https://verifier.example/response", responseURI: "https://verifier.example/response", wantAccepted: true},
		{name: "same URI with legacy scheme", clientURI: "https://verifier.example/response", responseURI: "https://verifier.example/response", scheme: "redirect_uri", wantAccepted: true},
		{name: "foreign URI", clientURI: "https://verifier.example/cb", responseURI: "https://verifier.example/elsewhere"},
		{name: "sub path without legacy scheme", clientURI: "https://verifier.example/app", responseURI: "https://verifier.example/app/cb"},
		{name: "sub path with legacy scheme", clientURI: "https://verifier.example/app", responseURI: "https://verifier.example/app/cb", scheme: "redirect_uri", wantAccepted: true},
		{name: "sub path under trailing slash with legacy scheme", clientURI: "https://verifier.example/app/", responseURI: "https://verifier.example/app/cb", scheme: "redirect_uri", wantAccepted: true},
		{name: "sibling path sharing a prefix", clientURI: "https://verifier.example/app", responseURI: "https://verifier.example/application", scheme: "redirect_uri"},
		{name: "sibling path", clientURI: "https://verifier.example/app/cb", responseURI: "https://verifier.example/app/other", scheme: "redirect_uri"},
		{name: "other host", clientURI: "https://verifier.example/app", responseURI: "https://attacker.example/app/cb", scheme: "redirect_uri"},
		{name: "other port", clientURI: "https://verifier.example/app", responseURI: "https://verifier.example:8443/app/cb", scheme: "redirect_uri"},
		{name: "root client path", clientURI: "https://verifier.example/", responseURI: "https://verifier.example/cb", scheme: "redirect_uri"},
		{name: "empty client path", clientURI: "https://verifier.example", responseURI: "https://verifier.example/cb", scheme: "redirect_uri"},
		{name: "plain http is never tolerated", clientURI: "http://verifier.example/app", responseURI: "http://verifier.example/app/cb", scheme: "redirect_uri", allowHTTP: true},
		{name: "other legacy scheme", clientURI: "https://verifier.example/app", responseURI: "https://verifier.example/app/cb", scheme: "x509_san_dns"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			values := draft24RedirectURIValues(tt.clientURI, tt.responseURI)
			if tt.scheme != "" {
				values.Set("client_id_scheme", tt.scheme)
			}
			// The error response a refusal sends never leaves the process:
			// these hosts are not served, and the outcome must not depend on it.
			var posted []string
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				posted = append(posted, r.URL.String())
				return nil, errors.New("no network in this test")
			})}
			p := &Oid4vpPresenter{AllowHTTP: tt.allowHTTP, HTTPClient: client}
			req, err := parseDraft24ForTest(p, finalQueryURI(values))
			if tt.wantAccepted {
				require.NoError(t, err)
				require.Equal(t, tt.responseURI, req.ResponseURI)
				return
			}
			require.Error(t, err)
			require.True(t, errors.Is(err, ErrResponseURIClientIDMismatch), "want ErrResponseURIClientIDMismatch, got %v", err)
			assertAuthzErrorCode(t, err, InvalidRequestError)
			for _, target := range posted {
				require.NotEqual(t, tt.responseURI, target, "the refused response_uri must receive nothing")
			}
		})
	}
}

// The refused response_uri is not the Verifier's, so the Draft24 error
// authorization response goes to the URI the Client Identifier authenticates,
// never to the one the request chose - the rule the Final path applies.
func TestDraft24RedirectURIClientIDMismatchAnswersTheClientIdentifier(t *testing.T) {
	attacker := newCountingResponseServer(t)
	verifier := newCountingResponseServer(t)
	values := draft24RedirectURIValues(verifier.server.URL+"/response", attacker.server.URL+"/post")
	p := &Oid4vpPresenter{AllowHTTP: true, HTTPClient: verifier.server.Client(), SendParseErrorResponses: true}
	_, err := parseDraft24ForTest(p, finalQueryURI(values))
	require.True(t, errors.Is(err, ErrResponseURIClientIDMismatch), "want ErrResponseURIClientIDMismatch, got %v", err)
	require.Equal(t, int32(0), attacker.calls.Load(), "the foreign response_uri must receive nothing")
	require.Equal(t, int32(1), verifier.calls.Load(), "the authenticated Client Identifier receives the error response")
}

// Draft24 keeps requiring the response_uri parameter for direct_post rather
// than defaulting it to the Client Identifier as the Final path does.
func TestDraft24RedirectURIClientIDStillRequiresResponseURI(t *testing.T) {
	values := draft24RedirectURIValues("https://verifier.example/response", "")
	values.Del("response_uri")
	_, err := parseDraft24ForTest((&Oid4vpPresenter{}), finalQueryURI(values))
	require.ErrorContains(t, err, "response_uri")
}

func TestLegacyRedirectURIResponseURIAllowedRejectsUnparsableURIs(t *testing.T) {
	require.False(t, legacyRedirectURIResponseURIAllowed("https://verifier.example/%zz", "https://verifier.example/app/cb"))
	require.False(t, legacyRedirectURIResponseURIAllowed("https://verifier.example/app", "https://verifier.example/%zz"))
}
