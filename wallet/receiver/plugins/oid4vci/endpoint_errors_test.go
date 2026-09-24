package oid4vci

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

// requireEndpointError recovers the stage classification of a failed endpoint
// and asserts the fields a caller reports from.
func requireEndpointError(t *testing.T, err error, stage Stage, status int, oauthError string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error")
	}
	var endpointError *EndpointError
	if !errors.As(err, &endpointError) {
		t.Fatalf("errors.As(*EndpointError) = false, err = %v", err)
	}
	if endpointError.Stage != stage {
		t.Errorf("Stage = %q, want %q", endpointError.Stage, stage)
	}
	if endpointError.StatusCode != status {
		t.Errorf("StatusCode = %d, want %d", endpointError.StatusCode, status)
	}
	if endpointError.OAuthError != oauthError {
		t.Errorf("OAuthError = %q, want %q", endpointError.OAuthError, oauthError)
	}
}

// Every endpoint of a Final issuance names itself when it refuses the request,
// so a caller reports which step failed without inspecting message text.
func TestEndpointErrorNamesTheFailedStage(t *testing.T) {
	status := http.StatusServiceUnavailable
	body := map[string]string{"error": "temporarily_unavailable"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = mockserver.JSONResponse(w, status, body)
	}))
	defer server.Close()
	receiver := &Oid4vciReceiver{HTTPClient: server.Client(), AllowHTTP: true}
	endpoint := mustURIField(t, server.URL+"/issuer")

	_, err := receiver.FetchIssuerMetadata(endpoint, types.Oid4vci)
	requireEndpointError(t, err, StageIssuerMetadata, status, "temporarily_unavailable")

	_, err = receiver.FetchAuthorizationServerMetadata(endpoint, types.Oid4vci)
	requireEndpointError(t, err, StageAuthorizationServerMetadata, status, "temporarily_unavailable")

	_, err = receiver.PushAuthorizationRequest(context.Background(), endpoint, types.PushedAuthorizationRequest{ResponseType: "code"}, types.ClientAuthentication{})
	requireEndpointError(t, err, StagePAR, status, "temporarily_unavailable")

	_, err = receiver.RequestNonce(context.Background(), endpoint)
	requireEndpointError(t, err, StageNonce, status, "temporarily_unavailable")

	_, err = receiver.RequestToken(t.Context(), endpoint, types.TokenRequest{GrantType: types.AuthorizationCode, Code: "code-1"}, types.ClientAuthentication{ClientAttestation: fixedAttestationHeaders(types.OAuthClientAttestationHeaders{}), DPoP: noopProofFactory})
	requireEndpointError(t, err, StageToken, status, "temporarily_unavailable")

	_, err = receiver.RequestToken(context.Background(), endpoint, types.TokenRequest{GrantType: types.PreAuthorizedCode, PreAuthorizedCode: "pre-1"}, types.ClientAuthentication{ClientAttestation: func() (types.OAuthClientAttestationHeaders, error) {
		return types.OAuthClientAttestationHeaders{}, nil
	}, DPoP: noopProofFactory})
	requireEndpointError(t, err, StageToken, status, "temporarily_unavailable")
}

// The token endpoint's RFC 6749 §5.2 error code is reported structurally, and
// the issuer's response body is not kept on the error.
func TestEndpointErrorReportsTheOAuthErrorWithoutTheBody(t *testing.T) {
	secret := "leaked-authorization-details"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = mockserver.JSONResponse(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_grant",
			"error_description": secret,
		})
	}))
	defer server.Close()
	receiver := &Oid4vciReceiver{HTTPClient: server.Client(), AllowHTTP: true}

	_, err := receiver.RequestToken(t.Context(), mustURIField(t, server.URL), types.TokenRequest{GrantType: types.AuthorizationCode, Code: "code-1"}, types.ClientAuthentication{ClientAttestation: fixedAttestationHeaders(types.OAuthClientAttestationHeaders{}), DPoP: noopProofFactory})
	requireEndpointError(t, err, StageToken, http.StatusBadRequest, "invalid_grant")
	var endpointError *EndpointError
	_ = errors.As(err, &endpointError)
	// A report built from the fields alone — which is what a wallet renders and
	// logs — carries the stage and the error code and nothing from the body.
	report := fmt.Sprintf("%s %d %s", endpointError.Stage, endpointError.StatusCode, endpointError.OAuthError)
	if strings.Contains(report, secret) {
		t.Errorf("the endpoint error fields must not carry the response body: %s", report)
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("the error message must not carry the response body: %s", err)
	}
}

// Every error string built from a refused response carries the status and the
// OAuth error code, never the raw response body.
func TestErrorStringsDoNotCarryTheResponseBody(t *testing.T) {
	const secret = "attacker-controlled-body-text"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/plain") {
			http.Error(w, secret, http.StatusBadRequest)
			return
		}
		_ = mockserver.JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "secret": secret})
	}))
	defer server.Close()
	receiver := &Oid4vciReceiver{HTTPClient: server.Client(), AllowHTTP: true}
	proof := "proof"
	calls := map[string]func(path string) error{
		"FetchAccessToken": func(path string) error {
			_, err := receiver.FetchAccessToken(types.Oid4vci, mustURIField(t, server.URL+path), "code", "")
			return err
		},
		"FetchNonce": func(path string) error {
			_, err := receiver.FetchNonce(types.Oid4vci, mustURIField(t, server.URL+path))
			return err
		},
		"ReceiveCredential": func(path string) error {
			_, err := receiver.ReceiveCredential(types.Oid4vci, mustURIField(t, server.URL+path), "cfg", nil, dpopAccessToken("access-1"), nil, nil, &types.CredentialRequestOptions{DPoPProofJWT: &proof})
			return err
		},
		"FetchIssuerMetadata": func(path string) error {
			_, err := receiver.FetchIssuerMetadata(mustURIField(t, server.URL+path), types.Oid4vci)
			return err
		},
		"PushAuthorizationRequest": func(path string) error {
			_, err := receiver.PushAuthorizationRequest(t.Context(), mustURIField(t, server.URL+path), types.PushedAuthorizationRequest{}, types.ClientAuthentication{})
			return err
		},
	}
	for name, call := range calls {
		for _, path := range []string{"/json", "/plain"} {
			err := call(path)
			if err == nil {
				t.Fatalf("%s %s: expected an error", name, path)
			}
			if strings.Contains(err.Error(), secret) {
				t.Errorf("%s %s: error carries the response body: %s", name, path, err)
			}
		}
	}
}

// The error_description a refusal carries is kept, bounded and reduced to the
// RFC 6749 Section 5.2 character set, so it is safe to log and render.
func TestCredentialErrorDescriptionIsBoundedAndSanitized(t *testing.T) {
	// JSON escapes for a newline and an ANSI escape sequence.
	description := `line one\nline two \u001b[31m` + strings.Repeat("x", 4096)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintf(w, `{"error":"invalid_proof","error_description":"%s"}`, description)
	}))
	defer server.Close()
	receiver := &Oid4vciReceiver{HTTPClient: server.Client(), AllowHTTP: true}

	_, err := postCredentialBody(t.Context(), receiver, mustURIField(t, server.URL), "access-1", []byte(`{}`), "application/json", fixedProof("proof"))
	var endpointError *types.CredentialEndpointError
	if !errors.As(err, &endpointError) {
		t.Fatalf("err = %v", err)
	}
	if len(endpointError.Description) > maxErrorDescriptionLength {
		t.Errorf("description length = %d, want at most %d", len(endpointError.Description), maxErrorDescriptionLength)
	}
	if strings.ContainsAny(endpointError.Description, "\n\x1b") || !strings.HasPrefix(endpointError.Description, "line one") {
		t.Errorf("description = %q", endpointError.Description)
	}

	_, err = receiver.RequestDraft13Credential(t.Context(), mustURIField(t, server.URL), dpopAccessToken("access-1"), types.Draft13CredentialRequest{Format: "vc+sd-jwt"}, fixedProof("proof"))
	var draft13Error *types.Draft13CredentialEndpointError
	if !errors.As(err, &draft13Error) || len(draft13Error.Description) > maxErrorDescriptionLength || strings.Contains(draft13Error.Description, "\x1b") {
		t.Errorf("draft13 error = %#v", draft13Error)
	}
}

// A failure with no HTTP response of its own still names its stage, and the
// sentinels underneath it stay reachable through the wrapper.
func TestEndpointErrorKeepsTheUnderlyingCause(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://elsewhere.example/metadata")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()
	receiver := &Oid4vciReceiver{HTTPClient: server.Client(), AllowHTTP: true}

	_, err := receiver.FetchAuthorizationServerMetadata(mustURIField(t, server.URL), types.Oid4vci)
	requireEndpointError(t, err, StageAuthorizationServerMetadata, 0, "")
	if !errors.Is(err, ErrHTTPRedirectNotAllowed) {
		t.Fatalf("errors.Is(ErrHTTPRedirectNotAllowed) = false, err = %v", err)
	}
}
