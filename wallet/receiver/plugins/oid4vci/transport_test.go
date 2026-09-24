package oid4vci

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"

	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

// OpenID4VCI 1.0 Section 8.2: a Credential Response the wallet asked to have
// encrypted is never accepted in plaintext.
func TestDecodeCredentialResponseRefusesPlaintextWhenEncryptionIsExpected(t *testing.T) {
	receiver := &Oid4vciReceiver{}
	plaintext := []byte(`{"credentials":[{"credential":"credential-1"}]}`)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_, err = receiver.DecodeCredentialResponse(plaintext, "application/json", nil, true)
	require.ErrorIs(t, err, types.ErrCredentialResponsePlaintext)

	_, err = receiver.DecodeCredentialResponse(plaintext, "application/json", privateKey, false)
	require.ErrorIs(t, err, types.ErrCredentialResponsePlaintext)

	// A nil *jose.JSONWebKey is no key: plaintext is what was asked for.
	var noKey *jose.JSONWebKey
	response, err := receiver.DecodeCredentialResponse(plaintext, "application/json", noKey, false)
	require.NoError(t, err)
	require.Len(t, response.Credentials, 1)
}

func TestDecodeCredentialResponseReportsItsFailures(t *testing.T) {
	receiver := &Oid4vciReceiver{}

	_, err := receiver.DecodeCredentialResponse([]byte("a.b.c.d.e"), "application/jwt", nil, false)
	require.ErrorIs(t, err, types.ErrCredentialResponseDecrypt)

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_, err = receiver.DecodeCredentialResponse([]byte("not-a-jwe"), "application/jwt", privateKey, false)
	require.ErrorIs(t, err, types.ErrCredentialResponseDecrypt)

	_, err = receiver.DecodeCredentialResponse([]byte("{"), "application/json", nil, false)
	require.ErrorIs(t, err, types.ErrCredentialResponseShape)
}

// A Token Request the plugin cannot send correctly is refused before any HTTP
// request leaves it.
func TestRequestTokenRejectsInvalidRequestsBeforeSending(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		mockserver.JSONResponse(w, http.StatusOK, map[string]string{"access_token": "access-1", "token_type": "Bearer"})
	}))
	t.Cleanup(server.Close)
	receiver := &Oid4vciReceiver{HTTPClient: server.Client(), AllowHTTP: true}
	assertion := func() (string, error) { return "assertion-jwt", nil }

	cases := map[string]struct {
		endpoint string
		request  types.TokenRequest
		auth     types.ClientAuthentication
	}{
		"unknown grant type": {
			endpoint: server.URL,
			request:  types.TokenRequest{GrantType: types.Password},
		},
		"authorization code without code": {
			endpoint: server.URL,
			request:  types.TokenRequest{GrantType: types.AuthorizationCode, CodeVerifier: "verifier"},
		},
		"pre-authorized code without code": {
			endpoint: server.URL,
			request:  types.TokenRequest{GrantType: types.PreAuthorizedCode},
		},
		"client assertion without client_id": {
			endpoint: server.URL,
			request:  types.TokenRequest{GrantType: types.AuthorizationCode, Code: "code-1"},
			auth:     types.ClientAuthentication{ClientAssertion: assertion},
		},
		"client assertion over plain HTTP to another host": {
			endpoint: "http://issuer.example/token",
			request:  types.TokenRequest{GrantType: types.AuthorizationCode, Code: "code-1", ClientID: "client-1"},
			auth:     types.ClientAuthentication{ClientAssertion: assertion},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := receiver.RequestToken(t.Context(), mustURIField(t, tc.endpoint), tc.request, tc.auth)
			require.Error(t, err)
			require.Zero(t, requests.Load(), "no request may be sent")
		})
	}
	_, err := receiver.RequestToken(t.Context(), mustURIField(t, server.URL), types.TokenRequest{GrantType: types.Password}, types.ClientAuthentication{})
	require.True(t, errors.Is(err, common.ErrInvalidInput), "err = %v", err)
}

// RFC 9396 authorization_details travel in the Token Request as a JSON array.
func TestRequestTokenSendsAuthorizationDetails(t *testing.T) {
	var form url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		form = r.PostForm
		mockserver.JSONResponse(w, http.StatusOK, map[string]string{"access_token": "access-1", "token_type": "Bearer"})
	}))
	t.Cleanup(server.Close)
	receiver := &Oid4vciReceiver{HTTPClient: server.Client(), AllowHTTP: true}

	_, err := receiver.RequestToken(t.Context(), mustURIField(t, server.URL), types.TokenRequest{
		GrantType: types.AuthorizationCode,
		Code:      "code-1",
		AuthorizationDetails: []types.CredentialIssuanceAuthorizationDetail{
			{Type: types.AuthorizationDetailTypeOpenIDCredential, CredentialConfigurationID: "pid"},
		},
	}, types.ClientAuthentication{})
	require.NoError(t, err)

	var details []types.CredentialIssuanceAuthorizationDetail
	require.NoError(t, json.Unmarshal([]byte(form.Get("authorization_details")), &details))
	require.Equal(t, "pid", details[0].CredentialConfigurationID)
	_, sent := form["client_id"]
	require.False(t, sent, "an empty client_id is omitted")
}

// RFC 9449 Section 8 applies to the PAR endpoint too: the retry carries a
// proof for the server's nonce and a fresh client_assertion.
func TestPushAuthorizationRequestRetriesDPoPNonceWithFreshCredentials(t *testing.T) {
	var forms []url.Values
	var proofs []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		forms = append(forms, r.PostForm)
		proofs = append(proofs, r.Header.Get("DPoP"))
		if len(forms) == 1 {
			w.Header().Set("DPoP-Nonce", "par-nonce")
			useDPoPNonceTokenChallenge(w)
			return
		}
		mockserver.JSONResponse(w, http.StatusCreated, map[string]any{"request_uri": "urn:request:1", "expires_in": 60})
	}))
	t.Cleanup(server.Close)
	receiver := &Oid4vciReceiver{HTTPClient: server.Client(), AllowHTTP: true}

	assertions := 0
	response, err := receiver.PushAuthorizationRequest(t.Context(), mustURIField(t, server.URL), types.PushedAuthorizationRequest{
		ResponseType: "code",
		ClientID:     "client-1",
		RedirectURI:  "https://wallet.example/callback",
	}, types.ClientAuthentication{
		DPoP: func(nonce string) (string, error) { return "proof-for-" + nonce, nil },
		ClientAssertion: func() (string, error) {
			assertions++
			return "assertion-" + string(rune('0'+assertions)), nil
		},
	})
	require.NoError(t, err)
	require.Equal(t, "urn:request:1", response.RequestURI)
	require.Equal(t, []string{"proof-for-", "proof-for-par-nonce"}, proofs)
	require.Len(t, forms, 2)
	require.NotEqual(t, forms[0].Get("client_assertion"), forms[1].Get("client_assertion"))
	require.Equal(t, types.ClientAssertionTypeJWTBearer, forms[1].Get("client_assertion_type"))
}
