package oid4vci

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

// newRedirectingOID4VCIEndpoint starts an endpoint that answers every request
// with a 307 to a second server, and reports how many requests that second
// server received. A 307 preserves the method and the body, so following it
// would replay a DPoP-bound body and its Authorization header at an origin the
// response chose, which is the reason A2 refuses every OID4VCI redirect.
func newRedirectingOID4VCIEndpoint(t *testing.T) (redirectingURL string, relayedRequests func() int) {
	t.Helper()
	var relayed atomic.Int64
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		relayed.Add(1)
		mockserver.JSONResponse(w, http.StatusOK, map[string]string{"credential_issuer": "https://relay.example"})
	}))
	t.Cleanup(relay.Close)

	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, relay.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redirecting.Close)

	return redirecting.URL, func() int { return int(relayed.Load()) }
}

func TestPushAuthorizationRequestRefusesRedirect(t *testing.T) {
	redirectingURL, relayedRequests := newRedirectingOID4VCIEndpoint(t)
	receiver := &Oid4vciReceiver{AllowHTTP: true}

	response, err := receiver.PushAuthorizationRequest(t.Context(),
		mustURIField(t, redirectingURL+"/par"),
		types.PushedAuthorizationRequest{ResponseType: "code", ClientID: "wallet", RedirectURI: "https://wallet.example/cb"}, types.ClientAuthentication{ClientAttestation: fixedAttestationHeaders(types.OAuthClientAttestationHeaders{ClientAttestation: "attestation", ClientAttestationPop: "pop"})})

	require.Error(t, err)
	assert.Nil(t, response)
	assert.ErrorIs(t, err, ErrHTTPRedirectNotAllowed)
	assert.Zero(t, relayedRequests(), "the pushed request must not reach the redirect target")
}

func TestRequestCredentialRefusesRedirect(t *testing.T) {
	redirectingURL, relayedRequests := newRedirectingOID4VCIEndpoint(t)
	receiver := &Oid4vciReceiver{AllowHTTP: true}

	response, err := postCredentialBody(t.Context(), receiver,
		mustURIField(t, redirectingURL+"/credential"),
		"access-1",
		[]byte(`{"credential_configuration_id":"cfg"}`),
		"application/json",
		noopProofFactory,
	)

	require.Error(t, err)
	assert.Nil(t, response)
	assert.ErrorIs(t, err, ErrHTTPRedirectNotAllowed)
	assert.Zero(t, relayedRequests(), "the credential request must not reach the redirect target")
}

func TestFetchIssuerMetadataRefusesRedirect(t *testing.T) {
	redirectingURL, relayedRequests := newRedirectingOID4VCIEndpoint(t)
	receiver := &Oid4vciReceiver{AllowHTTP: true}

	// Metadata gets no same-origin exemption: Section 12.2.2 fixes the metadata
	// path inside the Credential Issuer Identifier, so a redirect can only serve
	// the document from an origin the identifier does not name.
	metadata, err := receiver.FetchIssuerMetadata(mustURIField(t, redirectingURL), types.Oid4vci)

	require.Error(t, err)
	assert.Nil(t, metadata)
	assert.ErrorIs(t, err, ErrHTTPRedirectNotAllowed)
	assert.Zero(t, relayedRequests(), "the metadata request must not reach the redirect target")
}

func TestRequestNonceRefusesRedirect(t *testing.T) {
	redirectingURL, relayedRequests := newRedirectingOID4VCIEndpoint(t)
	receiver := &Oid4vciReceiver{AllowHTTP: true}

	response, err := receiver.RequestNonce(t.Context(), mustURIField(t, redirectingURL+"/nonce"))

	require.Error(t, err)
	assert.Nil(t, response)
	assert.ErrorIs(t, err, ErrHTTPRedirectNotAllowed)
	assert.Zero(t, relayedRequests(), "the nonce request must not reach the redirect target")
}
