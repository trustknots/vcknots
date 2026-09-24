package oid4vp

import (
	"context"
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
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/internal/testutil"
	"github.com/trustknots/vcknots/wallet/presenter/types"
	"github.com/trustknots/vcknots/wallet/profile"
)

// TestParsePresentationRequestReturnsRequestObjectSentinels drives four of the
// authentication failures through the public API, so the sentinels are proven
// reachable end to end and not only by classifyRequestObjectFailure.
func TestParsePresentationRequestReturnsRequestObjectSentinels(t *testing.T) {
	t.Run("expired", func(t *testing.T) {
		f := newRequestObjectFixture(t)
		claims := f.claims()
		claims["exp"] = f.now.Add(-time.Second).Unix()
		if _, err := f.parse(t, claims); !errors.Is(err, ErrRequestObjectExpired) {
			t.Fatalf("expired Request Object: %v", err)
		}
	})

	t.Run("audience mismatch", func(t *testing.T) {
		f := newRequestObjectFixture(t)
		claims := f.claims()
		claims["aud"] = "another-wallet"
		if _, err := f.parse(t, claims); !errors.Is(err, ErrRequestObjectAudienceMismatch) {
			t.Fatalf("audience mismatch: %v", err)
		}
	})

	t.Run("outer client_id mismatch", func(t *testing.T) {
		f := newRequestObjectFixture(t)
		claims := f.claims()
		claims["client_id"] = "x509_hash:not-the-object-client-id"
		if _, err := f.parse(t, claims); !errors.Is(err, ErrRequestObjectClientIDMismatch) {
			t.Fatalf("client_id mismatch: %v", err)
		}
	})

	t.Run("x509_hash mismatch", func(t *testing.T) {
		f := newRequestObjectFixture(t)
		wrong := "x509_hash:" + base64.RawURLEncoding.EncodeToString([]byte("wrong-leaf-hash"))
		claims := f.claims()
		claims["client_id"] = wrong
		uri := "openid4vp://authorize?" + url.Values{
			"client_id": {wrong},
			"request":   {f.sign(t, claims, nil)},
		}.Encode()
		if _, err := f.presenter().ParsePresentationRequest(uri); !errors.Is(err, ErrX509HashMismatch) {
			t.Fatalf("x509_hash mismatch: %v", err)
		}
	})

	t.Run("typ invalid", func(t *testing.T) {
		f := newRequestObjectFixture(t)
		options := (&jose.SignerOptions{}).
			WithType("JWT").
			WithHeader("x5c", []string{base64.StdEncoding.EncodeToString(f.leaf.Raw)})
		uri := "openid4vp://authorize?" + url.Values{
			"client_id": {f.clientID()},
			"request":   {f.sign(t, f.claims(), options)},
		}.Encode()
		if _, err := f.presenter().ParsePresentationRequest(uri); !errors.Is(err, ErrRequestObjectTypInvalid) {
			t.Fatalf("typ invalid: %v", err)
		}
	})

	t.Run("signature invalid", func(t *testing.T) {
		f := newRequestObjectFixture(t)
		other := newRequestObjectFixture(t)
		// Present f's certificate in x5c so the client_id binding passes, but
		// sign with other's key so verification fails.
		options := (&jose.SignerOptions{}).
			WithType("oauth-authz-req+jwt").
			WithHeader("x5c", []string{base64.StdEncoding.EncodeToString(f.leaf.Raw)})
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: other.key}, options)
		require.NoError(t, err)
		token, err := jwt.Signed(signer).Claims(f.claims()).Serialize()
		require.NoError(t, err)
		uri := "openid4vp://authorize?" + url.Values{
			"client_id": {f.clientID()},
			"request":   {token},
		}.Encode()
		if _, err := f.presenter().ParsePresentationRequest(uri); !errors.Is(err, ErrRequestObjectSignatureInvalid) {
			t.Fatalf("signature invalid: %v", err)
		}
	})

	t.Run("haip request_uri required", func(t *testing.T) {
		f := newRequestObjectFixture(t)
		p := f.presenterWith(requestFixtureOptions{Profile: profile.HAIP, Delivery: deliverByValue})
		uri := "openid4vp://authorize?" + url.Values{
			"client_id": {f.clientID()},
			"request":   {f.sign(t, f.claims(), nil)},
		}.Encode()
		if _, err := p.ParsePresentationRequest(uri); !errors.Is(err, ErrHAIPRequestURIRequired) {
			t.Fatalf("HAIP request_uri required: %v", err)
		}
	})
}

// TestPresentDCQLSendsEmptyVPTokenObject covers OID4VP 1.0 §8.1: a holder that
// declines every optional credential query answers with the empty vp_token
// object {}, not an omitted or null value.
func TestPresentDCQLSendsEmptyVPTokenObject(t *testing.T) {
	p, endpoint, forms, calls := dcqlTransportEndpoint(t)
	redirect, err := sendDCQLForTest(p, endpoint, map[string][]string{}, &types.PresentationRequest{})
	require.NoError(t, err)
	require.Equal(t, "https://verifier.example/complete", redirect)
	form := requireDCQLForm(t, forms, calls)
	require.Equal(t, "{}", form.Get("vp_token"))
	require.Len(t, form, 1)
}

// TestPresentDCQLVerifierResponseErrorHidesBody covers the leak boundary: a non-200
// verifier response becomes a *VerifierResponseError that carries only the
// status and the normalized OAuth error code, never the body.
func TestPresentDCQLVerifierResponseErrorHidesBody(t *testing.T) {
	const secret = "response-code-and-state-echoed-by-the-verifier"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid-Request!!","secret":"` + secret + `"}`))
	}))
	defer server.Close()
	endpoint, err := url.Parse(server.URL)
	require.NoError(t, err)

	p := &Oid4vpPresenter{}
	_, err = sendDCQLForTest(p, *endpoint, map[string][]string{"identity": {"presentation"}}, &types.PresentationRequest{})
	require.Error(t, err)

	var verifierErr *VerifierResponseError
	require.ErrorAs(t, err, &verifierErr)
	require.Equal(t, http.StatusBadRequest, verifierErr.StatusCode)
	require.Equal(t, "invalidrequest", verifierErr.OAuthError)
	require.Equal(t, "verifier returned status 400 (invalidrequest)", verifierErr.Error())
	require.NotContains(t, err.Error(), secret)
	require.NotContains(t, err.Error(), "secret")
}

// TestVerifierResponseErrorFormatting pins the two shapes of the diagnostic
// string: with and without an OAuth error code.
func TestVerifierResponseErrorFormatting(t *testing.T) {
	require.Equal(t, "verifier returned status 400 (invalid_request)",
		(&VerifierResponseError{StatusCode: 400, OAuthError: "invalid_request"}).Error())
	require.Equal(t, "verifier returned status 502",
		(&VerifierResponseError{StatusCode: 502}).Error())
}

// TestNormalizeOAuthErrorCode pins the [a-z_]{1,64} normalization.
func TestNormalizeOAuthErrorCode(t *testing.T) {
	require.Equal(t, "invalid_request", normalizeOAuthErrorCode("invalid_request"))
	require.Equal(t, "invalidrequest", normalizeOAuthErrorCode("invalid-Request 1"))
	require.Equal(t, "", normalizeOAuthErrorCode("日本語"))
	require.Len(t, normalizeOAuthErrorCode(strings.Repeat("a", 200)), 64)
}

// TestSubmitErrorResponse covers the error response to an admitted request:
// it posts error, error_description and the request's state to the request's
// response_uri, and returns the redirect_uri the verifier answered with.
func TestSubmitErrorResponse(t *testing.T) {
	captured := &url.Values{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type = %q", got)
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		*captured = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"redirect_uri":"https://verifier.example/complete"}`))
	}))
	defer server.Close()

	p := &Oid4vpPresenter{AllowHTTP: true}
	request := admitDirectPost(t, p, server.URL+"/response", "state-1")
	result, err := p.SubmitErrorResponse(context.Background(), request, "access_denied", "user declined")
	require.NoError(t, err)
	require.Equal(t, "https://verifier.example/complete", result.RedirectURI)
	require.False(t, result.Encrypted)
	require.Equal(t, "access_denied", captured.Get("error"))
	require.Equal(t, "user declined", captured.Get("error_description"))
	require.Equal(t, "state-1", captured.Get("state"))
	require.Empty(t, captured.Get("vp_token"))
}

// TestSubmitErrorResponseRefusesAnUnadmittedRequest: a handle admitted by
// another presenter instance is refused before anything is sent.
func TestSubmitErrorResponseRefusesAnUnadmittedRequest(t *testing.T) {
	reached := false
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached = true
	}))
	defer server.Close()
	request := admitDirectPost(t, &Oid4vpPresenter{AllowHTTP: true}, server.URL+"/response", "")

	_, err := (&Oid4vpPresenter{AllowHTTP: true}).SubmitErrorResponse(context.Background(), request, "access_denied", "")
	require.ErrorIs(t, err, ErrRequestNotAdmittedHere)
	require.False(t, reached)
}

// TestSubmitErrorResponseRefusesAnInvalidDescription: error_description must
// fit the RFC 6749 §4.1.2.1 character set, and a refusal carries a sentinel
// and reaches nothing.
func TestSubmitErrorResponseRefusesAnInvalidDescription(t *testing.T) {
	reached := false
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached = true
	}))
	defer server.Close()
	p := &Oid4vpPresenter{AllowHTTP: true}
	request := admitDirectPost(t, p, server.URL+"/response", "")

	for name, description := range map[string]string{
		"double quote":  `he said "no"`,
		"backslash":     `path\to\thing`,
		"newline":       "line1\nline2",
		"control byte":  "bell\x07",
		"outside ASCII": "利用者が拒否しました",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := p.SubmitErrorResponse(context.Background(), request, "access_denied", description)
			require.ErrorIs(t, err, ErrErrorDescriptionInvalid)
			require.False(t, reached, "a refused error response must not reach the verifier")
		})
	}
}

// TestSubmitErrorResponseEncryptsUnderDirectPostJWT: an error response to a
// direct_post.jwt request uses that Response Mode (OID4VP 1.0 §5.6), so it is
// encrypted to the Verifier's key.
func TestSubmitErrorResponseEncryptsUnderDirectPostJWT(t *testing.T) {
	recipient := testutil.NewP256Key(t)
	captured := &url.Values{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		*captured = r.PostForm
	}))
	defer server.Close()
	metadata, err := json.Marshal(map[string]any{
		"jwks": jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &recipient.PublicKey, KeyID: "enc", Use: "enc", Algorithm: "ECDH-ES"}}},
		"encrypted_response_enc_values_supported": []string{"A128GCM"},
	})
	require.NoError(t, err)
	p := &Oid4vpPresenter{AllowHTTP: true}
	request, err := p.ParseRequest(context.Background(), "openid4vp://authorize?"+url.Values{
		"client_id":       {"redirect_uri:" + server.URL + "/response"},
		"response_type":   {"vp_token"},
		"response_mode":   {"direct_post.jwt"},
		"nonce":           {"n"},
		"state":           {"state-1"},
		"client_metadata": {string(metadata)},
		"dcql_query":      {`{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]}}]}`},
	}.Encode())
	require.NoError(t, err)

	result, err := p.SubmitErrorResponse(context.Background(), request, "access_denied", "user declined")
	require.NoError(t, err)
	require.True(t, result.Encrypted)
	require.Len(t, *captured, 1)
	jwe, err := jose.ParseEncrypted(captured.Get("response"), []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A128GCM})
	require.NoError(t, err)
	plaintext, err := jwe.Decrypt(recipient)
	require.NoError(t, err)
	var payload map[string]string
	require.NoError(t, json.Unmarshal(plaintext, &payload))
	require.Equal(t, map[string]string{"error": "access_denied", "error_description": "user declined", "state": "state-1"}, payload)
}

// TestSubmitErrorResponseOverDCAPI: a DC API request's error response is the
// data object with the single member error (OID4VP 1.0 Appendix A.4).
func TestSubmitErrorResponseOverDCAPI(t *testing.T) {
	p := &Oid4vpPresenter{}
	request, err := p.ParseDCAPIRequest(context.Background(), dcapiUnsignedInvocation(t, "dc_api"))
	require.NoError(t, err)
	result, err := p.SubmitErrorResponse(context.Background(), request, "access_denied", "user declined")
	require.NoError(t, err)
	require.Equal(t, &types.DCAPIResponse{Protocol: DCAPIProtocolUnsigned, Data: map[string]any{"error": "access_denied"}}, result.DCAPIResponse)
}
