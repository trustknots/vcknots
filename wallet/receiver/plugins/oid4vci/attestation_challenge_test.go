package oid4vci

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

// A Challenge an authorization server provided is kept per server and per
// Client Instance Key: it is never presented with another key, which would
// link the keys, and the caller's own Challenge from the challenge endpoint
// takes precedence as the most recently received one.
func TestAttestationChallengeIsKeptPerServerAndKey(t *testing.T) {
	origin := url.URL{Scheme: "https", Host: "as.example"}
	prover := func(thumbprint, challenge string) exchange {
		return exchange{url: origin, attestation: types.ClientAttestationProver{
			KeyThumbprint: thumbprint,
			Challenge:     challenge,
			Headers: func(string) (types.OAuthClientAttestationHeaders, error) {
				return types.OAuthClientAttestationHeaders{}, nil
			},
		}}
	}
	receiver := &Oid4vciReceiver{}
	header := http.Header{}
	header.Set(attestationChallengeHeader, "challenge-a")
	receiver.rememberAttestationChallenge(prover("key-a", ""), header)

	if got := receiver.attestationChallengeFor(prover("key-a", "")); got != "challenge-a" {
		t.Fatalf("same key: %q", got)
	}
	if got := receiver.attestationChallengeFor(prover("key-b", "")); got != "" {
		t.Fatalf("a Challenge kept for key-a reached key-b: %q", got)
	}
	other := prover("key-a", "")
	other.url = url.URL{Scheme: "https", Host: "other-as.example"}
	if got := receiver.attestationChallengeFor(other); got != "" {
		t.Fatalf("a Challenge reached another server: %q", got)
	}
	if got := receiver.attestationChallengeFor(prover("key-a", "from-endpoint")); got != "from-endpoint" {
		t.Fatalf("the challenge endpoint's Challenge did not take precedence: %q", got)
	}
	if got := receiver.attestationChallengeFor(prover("", "")); got != "" {
		t.Fatalf("a prover without a key thumbprint got a kept Challenge: %q", got)
	}
}

// draft-ietf-oauth-attestation-based-client-auth-11 Section 6.3: "If the
// challenge endpoint response contains a DPoP-Nonce HTTP header field, a
// Client using DPoP MUST use its value as the nonce in subsequent DPoP
// proofs". The nonce goes to the next proof for the authorization server, and
// not to the Credential Issuer on the same origin.
func TestChallengeEndpointDPoPNonceSeedsTheNextAuthorizationServerProof(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("DPoP-Nonce", "challenge-endpoint-nonce")
		_ = mockserver.JSONResponse(w, http.StatusOK, map[string]string{"attestation_challenge": "challenge-1"})
	}))
	defer server.Close()
	receiver := &Oid4vciReceiver{HTTPClient: server.Client()}
	response, err := receiver.FetchClientAttestationChallenge(t.Context(), mustURIField(t, server.URL+"/challenge"))
	if err != nil {
		t.Fatal(err)
	}
	if response.AttestationChallenge != "challenge-1" {
		t.Fatalf("challenge = %q", response.AttestationChallenge)
	}
	origin, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	keyed := func(resource bool) exchange {
		return exchange{url: *origin, resourceServer: resource, dpop: testProver(fixedProof("proof"))}
	}
	if got := receiver.dpopNonceFor(keyed(true)); got != "" {
		t.Fatalf("the authorization server's nonce reached the resource server: %q", got)
	}
	if got := receiver.dpopNonceFor(keyed(false)); got != "challenge-endpoint-nonce" {
		t.Fatalf("next authorization server proof nonce = %q", got)
	}
}
