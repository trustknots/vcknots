package oid4vci

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

// recordingServer answers every request with handler and records the requests
// it received.
type recordingServer struct {
	*httptest.Server
	mu       sync.Mutex
	requests []*http.Request
	forms    []url.Values
}

func newRecordingServer(t *testing.T, handler func(attempt int, w http.ResponseWriter, r *http.Request)) *recordingServer {
	t.Helper()
	recorder := &recordingServer{}
	recorder.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		recorder.mu.Lock()
		recorder.requests = append(recorder.requests, r)
		recorder.forms = append(recorder.forms, r.PostForm)
		attempt := len(recorder.requests)
		recorder.mu.Unlock()
		handler(attempt, w, r)
	}))
	t.Cleanup(recorder.Close)
	return recorder
}

func (r *recordingServer) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.requests)
}

// countingProof records the nonce of every proof it builds.
type countingProof struct {
	nonces []string
}

func (p *countingProof) factory(nonce string) (string, error) {
	p.nonces = append(p.nonces, nonce)
	return "proof:" + nonce, nil
}

// RFC 9449 Section 8.2 lets a server send a fresh DPoP-Nonce on any response.
// A token error that is not use_dpop_nonce must not resend the single-use
// pre-authorized_code and the user's tx_code (OpenID4VCI 1.0 Section 6.3).
func TestTokenErrorWithDPoPNonceIsNotResent(t *testing.T) {
	server := newRecordingServer(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("DPoP-Nonce", "fresh-nonce")
		_ = mockserver.JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
	})
	receiver := &Oid4vciReceiver{HTTPClient: server.Client(), AllowHTTP: true}
	proof := &countingProof{}

	_, err := receiver.RequestToken(t.Context(), mustURIField(t, server.URL+"/token"), types.TokenRequest{GrantType: types.PreAuthorizedCode, PreAuthorizedCode: "pre-1", TxCode: "1234"}, types.ClientAuthentication{DPoP: proof.factory})

	requireEndpointError(t, err, StageToken, http.StatusBadRequest, "invalid_grant")
	if server.count() != 1 {
		t.Fatalf("token requests = %d, want 1: the pre-authorized_code and tx_code must be sent once", server.count())
	}
	if got := server.forms[0].Get("tx_code"); got != "1234" {
		t.Fatalf("tx_code = %q", got)
	}
	// The nonce is still remembered for the next request to that server.
	if got := receiver.dpopNonceFor(url.URL(mustURIField(t, server.URL+"/other"))); got != "fresh-nonce" {
		t.Fatalf("remembered DPoP nonce = %q, want fresh-nonce", got)
	}
}

// An invalid_proof refusal is the issuer rejecting the key proof. Resending
// the identical body would replay the same key proof JWT.
func TestCredentialErrorWithDPoPNonceIsNotResent(t *testing.T) {
	for _, code := range []string{"invalid_proof", "invalid_credential_request", "issuance_pending"} {
		t.Run(code, func(t *testing.T) {
			server := newRecordingServer(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("DPoP-Nonce", "fresh-nonce")
				_ = mockserver.JSONResponse(w, http.StatusBadRequest, map[string]string{"error": code})
			})
			receiver := &Oid4vciReceiver{HTTPClient: server.Client(), AllowHTTP: true}
			proof := &countingProof{}

			_, err := postCredentialBody(t.Context(), receiver, mustURIField(t, server.URL+"/credential"), "access-1", []byte(`{"proofs":{"jwt":["key-proof"]}}`), "application/json", proof.factory)

			var endpointError *types.CredentialEndpointError
			if !errors.As(err, &endpointError) || endpointError.Code != code {
				t.Fatalf("error = %v, want a %s credential endpoint error", err, code)
			}
			if server.count() != 1 || len(proof.nonces) != 1 {
				t.Fatalf("requests = %d, proofs = %d, want 1 each", server.count(), len(proof.nonces))
			}
		})
	}
}

func TestDraft13CredentialErrorWithDPoPNonceIsNotResent(t *testing.T) {
	server := newRecordingServer(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("DPoP-Nonce", "fresh-nonce")
		_ = mockserver.JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
	})
	receiver := &Oid4vciReceiver{HTTPClient: server.Client(), AllowHTTP: true}
	proof := &countingProof{}

	_, err := receiver.RequestDraft13Credential(t.Context(), mustURIField(t, server.URL+"/credential"), dpopAccessToken("access-1"), types.Draft13CredentialRequest{Format: "vc+sd-jwt"}, proof.factory)

	var endpointError *types.Draft13CredentialEndpointError
	if !errors.As(err, &endpointError) || endpointError.Code != "invalid_request" {
		t.Fatalf("error = %v, want invalid_request", err)
	}
	if server.count() != 1 {
		t.Fatalf("requests = %d, want 1", server.count())
	}
}

// RFC 9449 Sections 8 and 9: use_dpop_nonce is answered once with a proof for
// the supplied nonce, both at the token endpoint and at a resource server.
func TestUseDPoPNonceIsResentOnceWithTheFreshNonce(t *testing.T) {
	t.Run("authorization server", func(t *testing.T) {
		server := newRecordingServer(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("DPoP-Nonce", "as-nonce")
			useDPoPNonceTokenChallenge(w)
		})
		receiver := &Oid4vciReceiver{HTTPClient: server.Client(), AllowHTTP: true}
		proof := &countingProof{}

		_, err := receiver.RequestToken(t.Context(), mustURIField(t, server.URL+"/token"), types.TokenRequest{GrantType: types.PreAuthorizedCode, PreAuthorizedCode: "pre-1"}, types.ClientAuthentication{DPoP: proof.factory})

		requireEndpointError(t, err, StageToken, http.StatusBadRequest, "use_dpop_nonce")
		if server.count() != 2 || strings.Join(proof.nonces, ",") != ",as-nonce" {
			t.Fatalf("requests = %d, proof nonces = %q", server.count(), proof.nonces)
		}
	})
	t.Run("resource server", func(t *testing.T) {
		server := newRecordingServer(t, func(attempt int, w http.ResponseWriter, _ *http.Request) {
			if attempt == 1 {
				w.Header().Set("DPoP-Nonce", "rs-nonce")
				useDPoPNonceResourceChallenge(w)
				return
			}
			_ = mockserver.JSONResponse(w, http.StatusOK, map[string]string{"credential": "vc"})
		})
		receiver := &Oid4vciReceiver{HTTPClient: server.Client(), AllowHTTP: true}
		proof := &countingProof{}

		if _, err := postCredentialBody(t.Context(), receiver, mustURIField(t, server.URL+"/credential"), "access-1", []byte(`{}`), "application/json", proof.factory); err != nil {
			t.Fatal(err)
		}
		if server.count() != 2 || strings.Join(proof.nonces, ",") != ",rs-nonce" {
			t.Fatalf("requests = %d, proof nonces = %q", server.count(), proof.nonces)
		}
	})
}

// A request is not resent when the resend could not differ: no proof was
// sent, or the challenge names the nonce the proof already carried.
func TestUseDPoPNonceIsNotResentWhenNothingWouldChange(t *testing.T) {
	t.Run("no proof", func(t *testing.T) {
		server := newRecordingServer(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("DPoP-Nonce", "as-nonce")
			useDPoPNonceTokenChallenge(w)
		})
		receiver := &Oid4vciReceiver{HTTPClient: server.Client(), AllowHTTP: true}

		_, err := receiver.RequestToken(t.Context(), mustURIField(t, server.URL+"/token"), types.TokenRequest{GrantType: types.PreAuthorizedCode, PreAuthorizedCode: "pre-1"}, types.ClientAuthentication{})

		requireEndpointError(t, err, StageToken, http.StatusBadRequest, "use_dpop_nonce")
		if server.count() != 1 {
			t.Fatalf("requests = %d, want 1", server.count())
		}
	})
	t.Run("same nonce", func(t *testing.T) {
		server := newRecordingServer(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("DPoP-Nonce", "stale-nonce")
			useDPoPNonceResourceChallenge(w)
		})
		receiver := &Oid4vciReceiver{HTTPClient: server.Client(), AllowHTTP: true}
		endpoint := mustURIField(t, server.URL+"/credential")
		receiver.rememberDPoPNonce(url.URL(endpoint), "stale-nonce")
		proof := &countingProof{}

		_, err := postCredentialBody(t.Context(), receiver, endpoint, "access-1", []byte(`{}`), "application/json", proof.factory)

		var endpointError *types.CredentialEndpointError
		if !errors.As(err, &endpointError) || endpointError.StatusCode != http.StatusUnauthorized {
			t.Fatalf("error = %v, want the 401 credential endpoint error", err)
		}
		if server.count() != 1 {
			t.Fatalf("requests = %d, want 1", server.count())
		}
	})
}

// RFC 8414 Section 2 metadata endpoints are used as published: a token
// endpoint with a trailing slash is requested at that URL.
func TestTokenEndpointIsUsedVerbatim(t *testing.T) {
	var paths []string
	server := newRecordingServer(t, func(_ int, w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		_ = mockserver.JSONResponse(w, http.StatusOK, map[string]string{"access_token": "access-1", "token_type": "Bearer"})
	})
	receiver := &Oid4vciReceiver{HTTPClient: server.Client(), AllowHTTP: true}
	endpoint := mustURIField(t, server.URL+"/token/")

	if _, err := receiver.RequestToken(t.Context(), endpoint, types.TokenRequest{GrantType: types.PreAuthorizedCode, PreAuthorizedCode: "pre-1"}, types.ClientAuthentication{}); err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.FetchAccessToken(types.Oid4vci, endpoint, "pre-1", ""); err != nil {
		t.Fatal(err)
	}
	if strings.Join(paths, ",") != "/token/,/token/" {
		t.Fatalf("requested paths = %q, want the published /token/", paths)
	}
}
