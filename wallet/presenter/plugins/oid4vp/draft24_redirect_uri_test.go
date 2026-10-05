package oid4vp

import (
	"errors"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustknots/vcknots/wallet/experimental"
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

// Draft 24 §5.10.4: with the redirect_uri scheme the Client Identifier "is
// the Redirect URI (or Response URI when Response Mode direct_post is used)",
// so the Response URI is bound to it exactly. The pre-Draft 22
// client_id_scheme parameter is not a Draft 24 parameter and widens nothing.
func TestDraft24RedirectURIClientIDBindsResponseURI(t *testing.T) {
	tests := []struct {
		name         string
		clientURI    string
		responseURI  string
		scheme       string
		wantAccepted bool
	}{
		{name: "same URI", clientURI: "https://verifier.example/response", responseURI: "https://verifier.example/response", wantAccepted: true},
		{name: "same URI with a client_id_scheme parameter", clientURI: "https://verifier.example/response", responseURI: "https://verifier.example/response", scheme: "redirect_uri", wantAccepted: true},
		{name: "foreign URI", clientURI: "https://verifier.example/cb", responseURI: "https://verifier.example/elsewhere"},
		{name: "sub path", clientURI: "https://verifier.example/app", responseURI: "https://verifier.example/app/cb"},
		{name: "sub path with the pre-Draft 22 client_id_scheme", clientURI: "https://verifier.example/app", responseURI: "https://verifier.example/app/cb", scheme: "redirect_uri"},
		{name: "other host", clientURI: "https://verifier.example/app", responseURI: "https://attacker.example/app/cb", scheme: "redirect_uri"},
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
			p := &Oid4vpPresenter{HTTPClient: client}
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
	p := withExperimental(&Oid4vpPresenter{HTTPClient: verifier.server.Client(), SendParseErrorResponses: true}, experimental.Presenter{Transport: experimental.Transport{AllowHTTP: true}})
	_, err := parseDraft24ForTest(p, finalQueryURI(values))
	require.True(t, errors.Is(err, ErrResponseURIClientIDMismatch), "want ErrResponseURIClientIDMismatch, got %v", err)
	require.Equal(t, int32(0), attacker.calls.Load(), "the foreign response_uri must receive nothing")
	require.Equal(t, int32(1), verifier.calls.Load(), "the authenticated Client Identifier receives the error response")
}

// Draft 24 §5.10.4: "The Verifier MAY omit the redirect_uri Authorization
// Request parameter (or response_uri when Response Mode direct_post is used)",
// so the Response URI is the Client Identifier.
func TestDraft24RedirectURIClientIDDefaultsResponseURI(t *testing.T) {
	values := draft24RedirectURIValues("https://verifier.example/response", "")
	values.Del("response_uri")
	req, err := parseDraft24ForTest((&Oid4vpPresenter{}), finalQueryURI(values))
	require.NoError(t, err)
	require.Equal(t, "https://verifier.example/response", req.ResponseURI)
}
