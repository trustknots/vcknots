package wallet

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/acceptance"
	"github.com/trustknots/vcknots/wallet/common/observe"
	"github.com/trustknots/vcknots/wallet/internal/observetest"
	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// notifyTestEndpoint makes the fixture issuer advertise its Notification
// Endpoint.
func notifyTestEndpoint(f *finalIssuanceFixture) {
	f.includeNotification = true
}

// notifyTestNotification is the state a DPoP-bound issuance from the fixture
// issuer hands back for notification-1.
func (f *finalIssuanceFixture) notifyTestNotification() *IssuanceNotification {
	return &IssuanceNotification{
		Version:          IssuanceVersionFinal,
		CredentialIssuer: f.server.URL,
		NotificationID:   "notification-1",
		AccessToken:      &receiverTypes.CredentialIssuanceAccessToken{Token: "access-1", TokenType: "DPoP"},
	}
}

func TestNotifyIssuerSendsEachEventWithADPoPProof(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, notifyTestEndpoint)
	for _, event := range []NotificationEvent{
		NotificationCredentialAccepted,
		NotificationCredentialFailure,
		NotificationCredentialDeleted,
	} {
		description := ""
		if event == NotificationCredentialFailure {
			description = "Could not store the Credential. Out of storage."
		}
		require.NoError(t, fixture.wallet.NotifyIssuer(context.Background(), fixture.notifyTestNotification(), event, description))
	}

	require.Equal(t, []map[string]any{
		{"notification_id": "notification-1", "event": "credential_accepted"},
		{"notification_id": "notification-1", "event": "credential_failure", "event_description": "Could not store the Credential. Out of storage."},
		{"notification_id": "notification-1", "event": "credential_deleted"},
	}, fixture.notificationBodies)
	accessTokenHash := sha256.Sum256([]byte("access-1"))
	for _, headers := range fixture.notificationHeaders {
		require.Equal(t, "application/json", headers.Get("Content-Type"))
		require.Equal(t, "DPoP access-1", headers.Get("Authorization"))
		proof := headers.Get("DPoP")
		require.NotEmpty(t, proof)
		require.Equal(t, "POST", extractPayloadField(t, proof, "htm"))
		require.Equal(t, fixture.server.URL+"/notification", extractPayloadField(t, proof, "htu"))
		require.Equal(t, base64.RawURLEncoding.EncodeToString(accessTokenHash[:]), extractPayloadField(t, proof, "ath"))
	}
}

// A Bearer token carries no proof even when the wallet holds a DPoP key; the
// token_type is compared case-insensitively.
func TestNotifyIssuerPresentsABearerTokenWithoutAProof(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, notifyTestEndpoint)
	notification := fixture.notifyTestNotification()
	notification.AccessToken = &receiverTypes.CredentialIssuanceAccessToken{Token: "access-1", TokenType: "bearer"}

	require.NoError(t, fixture.wallet.NotifyIssuer(context.Background(), notification, NotificationCredentialAccepted, ""))
	require.Len(t, fixture.notificationHeaders, 1)
	require.Equal(t, "Bearer access-1", fixture.notificationHeaders[0].Get("Authorization"))
	require.Empty(t, fixture.notificationHeaders[0].Get("DPoP"))
}

// The endpoint is the notification_endpoint the issuer metadata advertises
// now.
func TestNotifyIssuerReadsTheEndpointFromIssuerMetadata(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, notifyTestEndpoint)
	require.NoError(t, fixture.wallet.NotifyIssuer(context.Background(), fixture.notifyTestNotification(), NotificationCredentialDeleted, ""))
	require.Equal(t, []string{"credential_deleted"}, fixture.notificationEvents)
	require.Equal(t, 1, fixture.issuerMetadataCalls)

	fixture.includeNotification = false
	err := fixture.wallet.NotifyIssuer(context.Background(), fixture.notifyTestNotification(), NotificationCredentialDeleted, "")
	require.ErrorIs(t, err, ErrNotificationEndpointMissing)
	require.Len(t, fixture.notificationEvents, 1)
}

// Every Section 11.1 rule is checked before a request leaves the wallet, and
// each refusal is a coded error.
func TestNotifyIssuerRefusesAnInvalidRequestBeforeSending(t *testing.T) {
	type input struct {
		notification *IssuanceNotification
		event        NotificationEvent
		description  string
		wallet       *Wallet
	}
	for name, tc := range map[string]struct {
		mutate func(f *finalIssuanceFixture, in *input)
		want   error
	}{
		"nil notification":        {func(_ *finalIssuanceFixture, in *input) { in.notification = nil }, ErrInvalidArgument},
		"another version":         {func(_ *finalIssuanceFixture, in *input) { in.notification.Version = IssuanceVersionDraft13 }, ErrIssuanceVersionMismatch},
		"missing issuer":          {func(_ *finalIssuanceFixture, in *input) { in.notification.CredentialIssuer = "" }, ErrIssuanceStateMismatch},
		"missing notification_id": {func(_ *finalIssuanceFixture, in *input) { in.notification.NotificationID = " " }, ErrNotificationIDMissing},
		"unknown event":           {func(_ *finalIssuanceFixture, in *input) { in.event = "credential_lost" }, ErrNotificationEventInvalid},
		"event in another case":   {func(_ *finalIssuanceFixture, in *input) { in.event = "Credential_Accepted" }, ErrNotificationEventInvalid},
		"double quote":            {func(_ *finalIssuanceFixture, in *input) { in.description = `say "no"` }, ErrNotificationEventDescriptionInvalid},
		"backslash":               {func(_ *finalIssuanceFixture, in *input) { in.description = `a\b` }, ErrNotificationEventDescriptionInvalid},
		"non-ASCII":               {func(_ *finalIssuanceFixture, in *input) { in.description = "保存失敗" }, ErrNotificationEventDescriptionInvalid},
		"control character":       {func(_ *finalIssuanceFixture, in *input) { in.description = "line\nbreak" }, ErrNotificationEventDescriptionInvalid},
		"missing access token":    {func(_ *finalIssuanceFixture, in *input) { in.notification.AccessToken = nil }, ErrNotificationAccessTokenMissing},
		"empty access token":      {func(_ *finalIssuanceFixture, in *input) { in.notification.AccessToken.Token = "" }, ErrNotificationAccessTokenMissing},
		"unsupported token_type":  {func(_ *finalIssuanceFixture, in *input) { in.notification.AccessToken.TokenType = "MAC" }, ErrTokenTypeUnsupported},
		"DPoP token without key":  {func(_ *finalIssuanceFixture, in *input) { in.wallet.dpop = DPoPConfig{} }, ErrNotificationDPoPKeyMissing},
		"DPoP token bound to another key": {
			func(_ *finalIssuanceFixture, in *input) { in.notification.DPoPKeyThumbprint = "another-thumbprint" },
			ErrDPoPKeyMismatch,
		},
		"issuer without a notification_endpoint": {
			func(f *finalIssuanceFixture, _ *input) { f.includeNotification = false },
			ErrNotificationEndpointMissing,
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newFinalIssuanceFixture(t, notifyTestEndpoint)
			in := &input{
				notification: fixture.notifyTestNotification(),
				event:        NotificationCredentialAccepted,
				wallet:       fixture.wallet,
			}
			tc.mutate(fixture, in)
			err := in.wallet.NotifyIssuer(context.Background(), in.notification, in.event, in.description)
			require.ErrorIs(t, err, tc.want)
			code, ok := ErrorCode(err)
			require.True(t, ok)
			require.NotEqual(t, "unclassified", code)
			require.Empty(t, fixture.notificationBodies, "no invalid request reached the issuer")
		})
	}
}

// HAIP Section 4: the notification presents a DPoP-bound token only.
func TestNotifyIssuerRefusesABearerTokenUnderHAIP(t *testing.T) {
	fixture := newHAIPIssuanceFixture(t, notifyTestEndpoint)
	notification := fixture.notifyTestNotification()
	notification.AccessToken.TokenType = "Bearer"
	err := fixture.wallet.NotifyIssuer(context.Background(), notification, NotificationCredentialAccepted, "")
	require.ErrorIs(t, err, ErrDPoPRequired)
	require.Empty(t, fixture.notificationBodies)
}

func TestNotifyIssuerReportsTheIssuerRefusal(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, notifyTestEndpoint, func(f *finalIssuanceFixture) {
		f.notificationHandler = func(w http.ResponseWriter, _ *http.Request) {
			mockserver.JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invalid_notification_id"})
		}
	})
	err := fixture.wallet.NotifyIssuer(context.Background(), fixture.notifyTestNotification(), NotificationCredentialAccepted, "")

	var endpointError *receiverTypes.CredentialEndpointError
	require.ErrorAs(t, err, &endpointError)
	require.Equal(t, http.StatusBadRequest, endpointError.StatusCode)
	require.Equal(t, "invalid_notification_id", endpointError.Code)
}

// RFC 9449 Section 8: a DPoP-Nonce challenge is answered once with a fresh
// proof.
func TestNotifyIssuerAnswersTheDPoPNonceChallenge(t *testing.T) {
	calls := 0
	fixture := newFinalIssuanceFixture(t, notifyTestEndpoint, func(f *finalIssuanceFixture) {
		f.notificationHandler = func(w http.ResponseWriter, _ *http.Request) {
			calls++
			if calls == 1 {
				w.Header().Set("DPoP-Nonce", "notification-nonce-1")
				mockserver.JSONResponse(w, http.StatusUnauthorized, map[string]string{"error": "use_dpop_nonce"})
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}
	})
	require.NoError(t, fixture.wallet.NotifyIssuer(context.Background(), fixture.notifyTestNotification(), NotificationCredentialAccepted, ""))
	require.Len(t, fixture.notificationHeaders, 2)
	first, err := jwsClaims(fixture.notificationHeaders[0].Get("DPoP"))
	require.NoError(t, err)
	require.NotContains(t, first, "nonce")
	require.Equal(t, "notification-nonce-1", extractPayloadField(t, fixture.notificationHeaders[1].Get("DPoP"), "nonce"))
}

// No OpenID4VCI endpoint redirects; following one would replay the access
// token and its proof to an origin the response chose.
func TestNotifyIssuerRefusesARedirect(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, notifyTestEndpoint, func(f *finalIssuanceFixture) {
		f.notificationHandler = func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/notification-elsewhere", http.StatusTemporaryRedirect)
		}
	})
	err := fixture.wallet.NotifyIssuer(context.Background(), fixture.notifyTestNotification(), NotificationCredentialAccepted, "")
	require.ErrorIs(t, err, ErrHTTPRedirectNotAllowed)
	require.Len(t, fixture.notificationBodies, 1)
}

func TestNotifyIssuerLabelsTheRequestsForAnObserver(t *testing.T) {
	recorder := &observetest.Recorder{}
	fixture := newFinalIssuanceFixture(t, notifyTestEndpoint, observeFixtureTransport(recorder))
	require.NoError(t, fixture.wallet.NotifyIssuer(context.Background(), fixture.notifyTestNotification(), NotificationCredentialAccepted, ""))

	require.Equal(t, []observe.Endpoint{observe.EndpointIssuerMetadata, observe.EndpointNotification},
		requireFixtureEndpointLabels(t, recorder.Exchanges()))
}

// Section 11 notifications are best effort: a credential_accepted the issuer
// refuses does not undo the credential the wallet stored.
func TestNotifyIssuerFailureKeepsTheStoredCredential(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, notifyTestEndpoint, func(f *finalIssuanceFixture) {
		f.notificationHandler = func(w http.ResponseWriter, _ *http.Request) {
			mockserver.JSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		}
	})
	result, err := fixture.receive(fixture.issuanceRequest())
	require.NoError(t, err)
	require.Len(t, result.Credentials, 1)
	require.NotNil(t, result.Notification)
	require.Equal(t, "notification-1", result.Notification.NotificationID)
	require.Empty(t, fixture.notificationEvents, "the library never notifies on its own")

	err = fixture.wallet.NotifyIssuer(context.Background(), result.Notification, NotificationCredentialAccepted, "")
	var endpointError *receiverTypes.CredentialEndpointError
	require.ErrorAs(t, err, &endpointError)
	require.Equal(t, []string{"credential_accepted"}, fixture.notificationEvents)

	entries, _, err := fixture.wallet.GetCredentialEntries(GetCredentialEntriesRequest{})
	require.NoError(t, err)
	require.Len(t, entries, 1)
}

// Refused credentials come back with the error and the notification, so the
// caller can report credential_failure; a failed report does not replace the
// refusal.
func TestRequestCredentialRefusalCarriesTheNotification(t *testing.T) {
	otherKey := newPrivateJWKForFinalVCITest(t, "other-holder-key")
	fixture := newFinalIssuanceFixture(t, notifyTestEndpoint, func(f *finalIssuanceFixture) {
		badCredential := f.issueCredential(otherKey, map[string]string{"given_name": "Taro"})
		f.credentialHandler = func(w http.ResponseWriter, _ *http.Request) {
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{
				"credentials":     []any{map[string]any{"credential": badCredential}},
				"notification_id": "notification-1",
			})
		}
		f.notificationHandler = func(w http.ResponseWriter, _ *http.Request) {
			mockserver.JSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		}
	})
	result, err := fixture.receive(fixture.issuanceRequest())
	require.ErrorIs(t, err, acceptance.ErrHolderBindingMismatch)
	require.ErrorContains(t, err, "not part of the request")
	require.NotNil(t, result)
	require.Empty(t, result.Credentials)
	require.NotNil(t, result.Notification)
	require.Empty(t, fixture.notificationEvents, "the library never notifies on its own")

	notifyErr := fixture.wallet.NotifyIssuer(context.Background(), result.Notification, NotificationCredentialFailure, "credential refused")
	var endpointError *receiverTypes.CredentialEndpointError
	require.ErrorAs(t, notifyErr, &endpointError)
	require.Equal(t, []string{"credential_failure"}, fixture.notificationEvents)

	entries, _, err := fixture.wallet.GetCredentialEntries(GetCredentialEntriesRequest{})
	require.NoError(t, err)
	require.Empty(t, entries)
}
