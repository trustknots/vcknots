package wallet

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// NotifyIssuer sends one OpenID4VCI 1.0 Notification Request (Section 11)
// reporting event for n. The endpoint is the issuer metadata's
// notification_endpoint, re-discovered; the request is validated before
// anything is sent. The issuer's refusal is a
// *receiverTypes.CredentialEndpointError.
func (w *Wallet) NotifyIssuer(ctx context.Context, n *IssuanceNotification, event NotificationEvent, description string) error {
	return classify(w.notifyIssuer(ctx, n, event, description))
}

func (w *Wallet) notifyIssuer(ctx context.Context, n *IssuanceNotification, event NotificationEvent, description string) error {
	if err := checkNotification(n, IssuanceVersionFinal, event, description); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !isDPoPAccessToken(n.AccessToken) && !strings.EqualFold(strings.TrimSpace(n.AccessToken.TokenType), "Bearer") {
		return fmt.Errorf("access token has token_type %q: %w", n.AccessToken.TokenType, ErrTokenTypeUnsupported)
	}
	if w.profile.IsHAIP() && !isDPoPAccessToken(n.AccessToken) {
		return fmt.Errorf("HAIP requires a DPoP-bound access token, the token has token_type %q: %w", n.AccessToken.TokenType, ErrDPoPRequired)
	}
	dpopKey, err := w.requireDPoPKey(n.DPoPKeyThumbprint, n.AccessToken, ErrNotificationDPoPKeyMissing)
	if err != nil {
		return err
	}
	transport, err := w.oid4vciTransport()
	if err != nil {
		return err
	}
	discovery, err := w.discoverIssuance(ctx, transport, nil, n.CredentialIssuer, offeredAuthorizationServer(""), false)
	if err != nil {
		return err
	}
	endpoint := discovery.issuerMetadata.NotificationEndpoint
	if endpoint == nil || endpoint.String() == "" {
		return ErrNotificationEndpointMissing
	}
	return transport.SendNotification(ctx, *endpoint, *n.AccessToken, receiverTypes.NotificationRequest{
		NotificationID:   n.NotificationID,
		Event:            string(event),
		EventDescription: description,
	}, dpopProofFactory(ctx, dpopKey, http.MethodPost, endpoint.String(), n.AccessToken.Token))
}

// checkNotification applies the rules OpenID4VCI 1.0 Section 11.1 and Draft
// 13 Section 10.1 share: a notification_id, one of the three events, an
// event_description within %x20-21 / %x23-5B / %x5D-7E, and an access token.
func checkNotification(n *IssuanceNotification, version IssuanceVersion, event NotificationEvent, description string) error {
	if n == nil {
		return invalidArgument("notification is required")
	}
	if n.Version != version {
		return fmt.Errorf("notification has version %q: %w", n.Version, ErrIssuanceVersionMismatch)
	}
	if n.CredentialIssuer == "" {
		return fmt.Errorf("notification does not name its credential issuer: %w", ErrIssuanceStateMismatch)
	}
	if strings.TrimSpace(n.NotificationID) == "" {
		return ErrNotificationIDMissing
	}
	switch event {
	case NotificationCredentialAccepted, NotificationCredentialFailure, NotificationCredentialDeleted:
	default:
		return fmt.Errorf("notification event %q: %w", event, ErrNotificationEventInvalid)
	}
	for index := 0; index < len(description); index++ {
		if b := description[index]; b < 0x20 || b > 0x7e || b == '"' || b == '\\' {
			return fmt.Errorf("event_description byte 0x%02x at offset %d: %w", b, index, ErrNotificationEventDescriptionInvalid)
		}
	}
	if n.AccessToken == nil || strings.TrimSpace(n.AccessToken.Token) == "" {
		return ErrNotificationAccessTokenMissing
	}
	return nil
}
