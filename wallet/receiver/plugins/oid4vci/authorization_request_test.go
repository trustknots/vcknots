package oid4vci

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

func TestOid4vciReceiver_PushAuthorizationRequestClientAssertion(t *testing.T) {
	t.Run("sends the assertion parameters when set", func(t *testing.T) {
		var captured url.Values
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			captured = r.Form
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{"request_uri": "urn:request:1", "expires_in": 60})
		}))
		defer server.Close()

		parsed, err := url.Parse(server.URL)
		require.NoError(t, err)
		receiver := &Oid4vciReceiver{AllowHTTP: true}
		_, err = receiver.PushAuthorizationRequest(t.Context(), common.URIField(*parsed), types.PushedAuthorizationRequest{
			ResponseType: "code",
			ClientID:     "client-1",
			RedirectURI:  "https://wallet.example/callback",
		}, types.ClientAuthentication{ClientAssertion: func() (string, error) { return "assertion-jwt", nil }})
		require.NoError(t, err)
		assert.Equal(t, "assertion-jwt", captured.Get("client_assertion"))
		assert.Equal(t, types.ClientAssertionTypeJWTBearer, captured.Get("client_assertion_type"))
	})

	t.Run("omits the assertion parameters when unset", func(t *testing.T) {
		var captured url.Values
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			captured = r.Form
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{"request_uri": "urn:request:1"})
		}))
		defer server.Close()

		parsed, err := url.Parse(server.URL)
		require.NoError(t, err)
		receiver := &Oid4vciReceiver{AllowHTTP: true}
		_, err = receiver.PushAuthorizationRequest(t.Context(), common.URIField(*parsed), types.PushedAuthorizationRequest{
			ResponseType: "code",
			ClientID:     "client-1",
			RedirectURI:  "https://wallet.example/callback",
		}, types.ClientAuthentication{})
		require.NoError(t, err)
		assert.Empty(t, captured.Get("client_assertion"))
		assert.Empty(t, captured.Get("client_assertion_type"))
	})
}

func TestOid4vciReceiver_PushAuthorizationRequestAuthorizationDetails(t *testing.T) {
	var captured url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		captured = r.Form
		mockserver.JSONResponse(w, http.StatusOK, map[string]any{"request_uri": "urn:request:1", "expires_in": 60})
	}))
	defer server.Close()

	parsed, err := url.Parse(server.URL)
	require.NoError(t, err)
	receiver := &Oid4vciReceiver{AllowHTTP: true}
	_, err = receiver.PushAuthorizationRequest(t.Context(), common.URIField(*parsed), types.PushedAuthorizationRequest{
		ResponseType: "code",
		ClientID:     "client-1",
		RedirectURI:  "https://wallet.example/callback",
		AuthorizationDetails: []map[string]any{
			{
				"type":                        types.AuthorizationDetailTypeOpenIDCredential,
				"credential_configuration_id": "pid",
			},
		},
	}, types.ClientAuthentication{})
	require.NoError(t, err)

	assert.Empty(t, captured.Get("scope"), "scope must be omitted when authorization_details is used")
	var details []map[string]any
	require.NoError(t, json.Unmarshal([]byte(captured.Get("authorization_details")), &details))
	require.Len(t, details, 1)
	assert.Equal(t, types.AuthorizationDetailTypeOpenIDCredential, details[0]["type"])
	assert.Equal(t, "pid", details[0]["credential_configuration_id"])
}
