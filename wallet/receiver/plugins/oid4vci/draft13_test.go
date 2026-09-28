package oid4vci

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

func TestDecodeDraft13CredentialResponse(t *testing.T) {
	t.Run("the singular credential member", func(t *testing.T) {
		response, err := decodeDraft13CredentialResponse([]byte(`{"credential":"issued","notification_id":"n-1","c_nonce":"fresh","c_nonce_expires_in":60}`))
		require.NoError(t, err)
		require.Equal(t, "issued", response.Credential)
		require.Equal(t, "n-1", response.NotificationID)
		require.Equal(t, "fresh", response.CNonce)
		require.Equal(t, 60, *response.CNonceExpiresIn)
	})
	t.Run("a deferred transaction keeps the interval an issuer names", func(t *testing.T) {
		response, err := decodeDraft13CredentialResponse([]byte(`{"transaction_id":"t-1","interval":9}`))
		require.NoError(t, err)
		require.Empty(t, response.Credential)
		require.Equal(t, "t-1", response.TransactionID)
		require.Equal(t, 9, response.Interval)
	})
	t.Run("a Final-shaped array holding one credential", func(t *testing.T) {
		response, err := decodeDraft13CredentialResponse([]byte(`{"credentials":[{"credential":"issued"}]}`))
		require.NoError(t, err)
		require.Equal(t, "issued", response.Credential)
	})
	t.Run("an object credential travels as its JSON document", func(t *testing.T) {
		response, err := decodeDraft13CredentialResponse([]byte(`{"credential":{"id":"urn:example"}}`))
		require.NoError(t, err)
		require.JSONEq(t, `{"id":"urn:example"}`, response.Credential)
	})
	t.Run("more than one credential is refused", func(t *testing.T) {
		_, err := decodeDraft13CredentialResponse([]byte(`{"credentials":[{"credential":"a"},{"credential":"b"}]}`))
		require.ErrorContains(t, err, "carries 2 credentials")
	})
	t.Run("an empty body is refused", func(t *testing.T) {
		_, err := decodeDraft13CredentialResponse([]byte(" "))
		require.Error(t, err)
	})
}

func TestNewDraft13CredentialEndpointError(t *testing.T) {
	endpointError := newDraft13CredentialEndpointError(http.StatusBadRequest, "application/json", []byte(`{"error":"invalid_proof","error_description":"stale","c_nonce":"fresh","interval":3}`), " dpop-nonce ")
	require.Equal(t, "invalid_proof", endpointError.Code)
	require.Equal(t, "stale", endpointError.Description)
	require.Equal(t, "fresh", endpointError.CNonce)
	require.Equal(t, 3, endpointError.Interval)
	require.Equal(t, "dpop-nonce", endpointError.DPoPNonce)
	require.True(t, errors.Is(endpointError, types.ErrDraft13InvalidProof))
	require.False(t, errors.Is(endpointError, types.ErrDraft13IssuancePending))
	require.Equal(t, "draft13_credential_invalid_proof", endpointError.ErrorCode())

	// A body that is not JSON is never read: only the status is reported.
	opaque := newDraft13CredentialEndpointError(http.StatusBadGateway, "text/html", []byte(`{"error":"invalid_proof"}`), "")
	require.Empty(t, opaque.Code)
	require.Equal(t, "draft13_credential_endpoint_failed", opaque.ErrorCode())
	require.Equal(t, "draft13 credential endpoint returned HTTP 502", opaque.Error())
}
