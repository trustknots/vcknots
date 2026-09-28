package wallet

import (
	"fmt"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/acceptance"
	"github.com/trustknots/vcknots/wallet/attestation"
	"github.com/trustknots/vcknots/wallet/profile"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// An OpenID4VCI issuance runs in stages, and a caller may persist the state
// between them and resume in another process:
//
//	BeginIssuance -> (browser) -> AuthorizeIssuance ----\
//	AuthorizePreAuthorizedIssuance ---------------------+-> RequestCredential
//	RequestCredential -> RequestDeferredCredential (while Deferred is set)
//	RequestCredential or RequestDeferredCredential -> NotifyIssuer
//
// The state types (IssuanceAuthorization, IssuanceGrant, DeferredIssuance,
// IssuanceNotification) are JSON and hold identifiers and secrets only. Every
// stage re-discovers the issuer and authorization server metadata, checks the
// state against the wallet's Config, and takes no endpoint from the state.
// Each state records the profile of the flow (its Profile field, in the text
// form of profile.Profile), and a stage refuses a state recorded under
// another profile than the wallet runs (ErrIssuanceProfileMismatch), so a
// flow never continues under other Options than it began with. A caller that
// runs the stages in different processes builds each stage's wallet with
// the state's Profile.
//
// The state is a bearer secret: it holds a PKCE verifier, an access token or a
// response decryption key. Store it where only the wallet can read it, protect
// it against modification and keep it out of logs.
//
// The library never polls a deferred transaction and never sends a
// notification on its own.

// AuthorizationRequestType selects how the Credential Configuration is
// requested at the authorization endpoint (OpenID4VCI 1.0 Sections 5.1.1 and
// 5.1.2). The zero value uses scope when the configuration advertises one and
// authorization_details otherwise. HAIP allows scope only (HAIP Section 4.3).
type AuthorizationRequestType string

const (
	// AuthorizationRequestScope requests the configuration with its scope value.
	AuthorizationRequestScope AuthorizationRequestType = "scope"
	// AuthorizationRequestDetails requests the configuration with an
	// openid_credential authorization_details entry.
	AuthorizationRequestDetails AuthorizationRequestType = "authorization_details"
)

// IssuanceRequest starts an Authorization Code Flow issuance.
type IssuanceRequest struct {
	// CredentialOffer is the offer the holder accepted; it must carry an
	// authorization_code grant, or no grants at all, in which case the
	// authorization server metadata must support the authorization_code grant
	// (OpenID4VCI 1.0 and Draft 13 Section 4.1.1). Nil starts a
	// wallet-initiated issuance (OpenID4VCI 1.0 Section 5), which only the 1.0
	// methods support.
	CredentialOffer *CredentialOffer
	// CredentialIssuer is the Credential Issuer Identifier of a
	// wallet-initiated issuance. It must be empty when CredentialOffer is set.
	CredentialIssuer string
	// CredentialConfigurationID selects the configuration to request. With an
	// offer it must be one the offer lists, and empty selects the first;
	// without one it is required.
	CredentialConfigurationID string
	AuthorizationRequestType  AuthorizationRequestType
	// Acceptance is the acceptance policy of this issuance: it overrides
	// Config.CredentialAcceptance, and the IssuanceAuthorization and the
	// IssuanceGrant carry it to RequestCredential. One of the two is required,
	// and without either nothing is sent (ErrCredentialAcceptancePolicyRequired),
	// so no authorization is obtained for a credential the wallet would refuse.
	Acceptance *acceptance.Policy
}

// PreAuthorizedIssuanceRequest starts a Pre-Authorized Code Flow issuance
// (OpenID4VCI 1.0 Section 4.1.1).
type PreAuthorizedIssuanceRequest struct {
	// CredentialOffer must carry a pre-authorized_code grant.
	CredentialOffer *CredentialOffer
	// CredentialConfigurationID selects one of the offered configurations;
	// empty selects the first.
	CredentialConfigurationID string
	// TxCode is the Transaction Code the holder entered. It is required, and
	// only permitted, when the grant carries a tx_code object (Section 6.1).
	TxCode string
	// AuthorizationServer overrides the grant's authorization_server hint; it
	// must be one of the issuer metadata's authorization_servers.
	AuthorizationServer string
	// Acceptance is the acceptance policy of this issuance: it overrides
	// Config.CredentialAcceptance, and the IssuanceGrant carries it to
	// RequestCredential. One of the two is required, and without either the
	// pre-authorized code is not redeemed (ErrCredentialAcceptancePolicyRequired).
	Acceptance *acceptance.Policy
}

// CredentialRequest holds the per-request inputs of RequestCredential.
type CredentialRequest struct {
	// CredentialIdentifier selects the Credential Dataset to request: one of
	// the grant's CredentialIdentifiers. Empty selects the first. It must be
	// empty when the grant has none.
	CredentialIdentifier string
	// HolderKeys are the keys the credentials are bound to, one key proof
	// each. More than one requests a batch (OpenID4VCI 1.0 Section 8.2), up to
	// the issuer's batch_size. Draft 13 takes at most one.
	HolderKeys []IKeyEntry
	// KeyAttestation is an Appendix D key attestation obtained outside the
	// wallet for the grant's c_nonce. It takes precedence over
	// Config.Attestation.Key. Draft 13 has no key attestation.
	KeyAttestation *attestation.KeyAttestation
	// IncludeKeyAttestation sends a key attestation although the issuer does
	// not require one.
	IncludeKeyAttestation bool
	// Acceptance is the acceptance policy of this request: it overrides the
	// policy the grant carries (IssuanceGrant.Acceptance) and
	// Config.CredentialAcceptance for the credentials of this request, and of
	// the Deferred issuance it may return. The library fills the issuance
	// context the policy needs (the Credential Issuer Identifier and the
	// Credential Format). One of them is required, and the request is not sent
	// without it (ErrCredentialAcceptancePolicyRequired).
	Acceptance *acceptance.Policy
}

// IssuanceAuthorization is the state between BeginIssuance and
// AuthorizeIssuance. It is a bearer secret (CodeVerifier, ClientInstanceKey)
// and is used once:
// discard it after AuthorizeIssuance, whether that succeeded or failed.
type IssuanceAuthorization struct {
	// Profile is the profile the flow runs under: the wallet's 1.0 profile,
	// or profile.Draft13 for a Draft 13 state. Its Version is the
	// OpenID4VCI version of the state, which the other version's methods
	// refuse (ErrIssuanceVersionMismatch).
	Profile profile.Profile `json:"profile"`
	// AuthorizationURL is the authorization request to open in the holder's
	// browser.
	AuthorizationURL string `json:"authorization_url"`
	// State is the RFC 6749 Section 4.1.1 state the redirect must echo.
	State string `json:"state"`
	// CodeVerifier is the RFC 7636 PKCE verifier. Secret.
	CodeVerifier              string `json:"code_verifier"`
	CredentialIssuer          string `json:"credential_issuer"`
	CredentialConfigurationID string `json:"credential_configuration_id"`
	// AuthorizationServer is the RFC 8414 issuer identifier of the
	// authorization server the request was sent to.
	AuthorizationServer string `json:"authorization_server"`
	// ClientID and RedirectURI are the Config values the request used;
	// AuthorizeIssuance requires the Config to still name them.
	ClientID    string `json:"client_id"`
	RedirectURI string `json:"redirect_uri"`
	// AuthorizationDetailsRequested records that the request used
	// authorization_details, which makes them required in the Token Response
	// (OpenID4VCI 1.0 Section 6.2).
	AuthorizationDetailsRequested bool `json:"authorization_details_requested,omitempty"`
	// RequestURIExpiresAt is the RFC 9126 request_uri expiry; zero when the
	// request was not pushed.
	RequestURIExpiresAt time.Time `json:"request_uri_expires_at,omitempty"`
	// ClientInstanceKey is the ephemeral private key the Client Attestation
	// of the Pushed Authorization Request bound, set when the wallet chose a
	// key for this flow (AttestationConfig.ClientKey unset). The token
	// request binds the same key, since the authorization server may bind
	// the code to it (draft-ietf-oauth-attestation-based-client-auth
	// Section 10.4). Secret.
	ClientInstanceKey *jose.JSONWebKey `json:"client_instance_key,omitempty"`
	// Acceptance is the IssuanceRequest.Acceptance the flow began with. A
	// policy holds functions and trust material, so it is not serialized: a
	// caller that stores the state sets it again before AuthorizeIssuance.
	Acceptance *acceptance.Policy `json:"-"`
	// AcceptanceOverridden records that the flow began with an
	// IssuanceRequest.Acceptance, and is serialized. While it is set,
	// AuthorizeIssuance refuses a state whose Acceptance is nil with
	// ErrCredentialAcceptancePolicyRequired, before the code is exchanged,
	// instead of continuing under Config.CredentialAcceptance.
	AcceptanceOverridden bool `json:"acceptance_overridden,omitempty"`

	cache *issuanceMetadataCache
}

// RequestURIExpired reports whether the pushed request_uri can no longer be
// used at the authorization endpoint at now. It bounds opening
// AuthorizationURL only; the redirect may arrive later.
func (a *IssuanceAuthorization) RequestURIExpired(now time.Time) bool {
	if a == nil || a.RequestURIExpiresAt.IsZero() {
		return false
	}
	return !now.Before(a.RequestURIExpiresAt)
}

// IssuanceGrant is the state between the token exchange and
// RequestCredential. It is a bearer secret (AccessToken) and is used once
// per Credential Dataset: discard it after RequestCredential, keeping only the
// Deferred or Notification of its result, unless CredentialIdentifiers lists
// more datasets the holder wants, each requested with its own
// RequestCredential (CredentialRequest.CredentialIdentifier). A call that
// stopped before sending anything, such as with *KeyAttestationRequiredError,
// may be repeated with it.
type IssuanceGrant struct {
	Profile                   profile.Profile `json:"profile"`
	CredentialIssuer          string          `json:"credential_issuer"`
	CredentialConfigurationID string          `json:"credential_configuration_id"`
	// AuthorizationServer is the RFC 8414 issuer identifier of the server
	// that issued the token.
	AuthorizationServer string                                       `json:"authorization_server"`
	AccessToken         *receiverTypes.CredentialIssuanceAccessToken `json:"access_token"`
	// CredentialIdentifiers are the Section 6.2 credential_identifiers of the
	// requested configuration, each naming a Credential Dataset the access
	// token can be used for, in the order the server listed them. A
	// Credential Request names one of them (CredentialRequest.
	// CredentialIdentifier, the first by default). Empty means the request
	// names the configuration (1.0 Section 8.2) or, in Draft 13, its format
	// (Draft 13 Section 7.2).
	CredentialIdentifiers []string `json:"credential_identifiers,omitempty"`
	// CNonce is the c_nonce the key proofs and a key attestation must carry;
	// empty when the issuer has no Nonce Endpoint.
	CNonce string `json:"c_nonce,omitempty"`
	// DPoPKeyThumbprint is the RFC 7638 thumbprint of the key a DPoP-bound
	// token is bound to; the stages that present the token require
	// Config.DPoP.Key to have it (ErrDPoPKeyMismatch).
	DPoPKeyThumbprint string `json:"dpop_key_thumbprint,omitempty"`
	// KeyAttestationRequired records that the configuration lists
	// key_attestations_required (OpenID4VCI 1.0 Appendix D).
	KeyAttestationRequired bool `json:"key_attestation_required,omitempty"`
	// Acceptance is the IssuanceRequest.Acceptance or
	// PreAuthorizedIssuanceRequest.Acceptance the flow began with; a
	// CredentialRequest.Acceptance overrides it. It is not serialized: a
	// caller that stores the state sets it again, or passes
	// CredentialRequest.Acceptance, before RequestCredential.
	Acceptance *acceptance.Policy `json:"-"`
	// AcceptanceOverridden records that the flow began with its own policy,
	// and is serialized. While it is set, RequestCredential without a
	// CredentialRequest.Acceptance refuses a grant whose Acceptance is nil with
	// ErrCredentialAcceptancePolicyRequired, before anything is sent, instead
	// of accepting the credentials under Config.CredentialAcceptance.
	AcceptanceOverridden bool `json:"acceptance_overridden,omitempty"`

	cache *issuanceMetadataCache
}

// carryAcceptance records on g the per-request policy its flow began with;
// nil records none, and Config.CredentialAcceptance applies.
func (g *IssuanceGrant) carryAcceptance(policy *acceptance.Policy) *IssuanceGrant {
	g.Acceptance, g.AcceptanceOverridden = policy, policy != nil
	return g
}

// DeferredIssuance is a pending deferred transaction (OpenID4VCI 1.0 Section
// 9). It is a bearer secret (AccessToken, ResponseDecryptionKey). Each
// RequestDeferredCredential uses it once: poll again with the result's
// Deferred, and discard it when the credentials are issued or the transaction
// fails.
type DeferredIssuance struct {
	Profile                   profile.Profile                              `json:"profile"`
	CredentialIssuer          string                                       `json:"credential_issuer"`
	CredentialConfigurationID string                                       `json:"credential_configuration_id"`
	TransactionID             string                                       `json:"transaction_id"`
	AccessToken               *receiverTypes.CredentialIssuanceAccessToken `json:"access_token"`
	// Interval is how long the issuer asked the wallet to wait before the
	// next request; zero when it named none. The library does not wait.
	Interval time.Duration `json:"interval,omitempty"`
	// HolderKeys are the public keys the credentials are bound to.
	HolderKeys []jose.JSONWebKey `json:"holder_keys,omitempty"`
	// ResponseDecryptionKey is the ephemeral private key of an encrypted
	// Credential Response. Secret.
	ResponseDecryptionKey *jose.JSONWebKey `json:"response_decryption_key,omitempty"`
	DPoPKeyThumbprint     string           `json:"dpop_key_thumbprint,omitempty"`
	// Acceptance is the per-request policy this issuance was requested
	// under: the CredentialRequest.Acceptance, or else the policy the
	// IssuanceGrant carried. A policy holds functions and trust material, so
	// it is not serialized: a caller that stores the state sets it again
	// before RequestDeferredCredential.
	Acceptance *acceptance.Policy `json:"-"`
	// AcceptanceOverridden records that the issuance was requested under a
	// per-request policy, and is serialized. While it is set,
	// RequestDeferredCredential refuses a DeferredIssuance whose Acceptance is
	// nil with ErrCredentialAcceptancePolicyRequired, before anything is sent,
	// instead of accepting the credentials under Config.CredentialAcceptance.
	AcceptanceOverridden bool `json:"acceptance_overridden,omitempty"`

	cache *issuanceMetadataCache
}

// IssuanceNotification is what NotifyIssuer needs to report the fate of issued
// credentials (OpenID4VCI 1.0 Section 11). It is a bearer secret
// (AccessToken) and is used once: discard it after NotifyIssuer.
type IssuanceNotification struct {
	Profile           profile.Profile                              `json:"profile"`
	CredentialIssuer  string                                       `json:"credential_issuer"`
	NotificationID    string                                       `json:"notification_id"`
	AccessToken       *receiverTypes.CredentialIssuanceAccessToken `json:"access_token"`
	DPoPKeyThumbprint string                                       `json:"dpop_key_thumbprint,omitempty"`
}

// IssuanceResult is the outcome of RequestCredential or
// RequestDeferredCredential: credentials, or a transaction still pending.
type IssuanceResult struct {
	// Credentials were verified under the request's Acceptance policy (or
	// Config.CredentialAcceptance) and, unless the wallet is storeless, saved.
	Credentials []*SavedCredential
	// Deferred is set while the issuer has not issued the credentials yet.
	Deferred *DeferredIssuance
	// Notification is set when the issuer asked to be notified. When the
	// credentials were refused, it comes with the error so the caller can
	// report credential_failure.
	Notification *IssuanceNotification
	// CredentialResponse is the decoded response.
	CredentialResponse *receiverTypes.CredentialResponse
}

// NotificationEvent is the event of a Notification Request (OpenID4VCI 1.0
// Section 11.1).
type NotificationEvent string

const (
	// NotificationCredentialAccepted reports that the credential was stored.
	NotificationCredentialAccepted NotificationEvent = "credential_accepted"
	// NotificationCredentialFailure reports an unsuccessful issuance not caused
	// by a holder action.
	NotificationCredentialFailure NotificationEvent = "credential_failure"
	// NotificationCredentialDeleted reports an unsuccessful issuance caused by a
	// holder action, such as deleting or rejecting the credential.
	NotificationCredentialDeleted NotificationEvent = "credential_deleted"
)

// CredentialOffer represents a credential offer from an issuer.
type CredentialOffer struct {
	CredentialIssuer           *url.URL                         `json:"credential_issuer"`
	CredentialConfigurationIDs []string                         `json:"credential_configuration_ids"`
	Grants                     map[string]*CredentialOfferGrant `json:"grants"`
}

// CredentialOfferGrant represents a grant in a credential offer.
type CredentialOfferGrant struct {
	PreAuthorizedCode string  `json:"pre-authorized_code"`
	IssuerState       string  `json:"issuer_state,omitempty"`
	TxCode            *TxCode `json:"tx_code,omitempty"`
	// AuthorizationServer is the authorization_server grant parameter; it
	// must be one of the issuer metadata's authorization_servers.
	AuthorizationServer string `json:"authorization_server,omitempty"`
}

// TxCode describes the transaction code expected by the issuer.
type TxCode struct {
	InputMode   string `json:"input_mode,omitempty"`
	Length      int    `json:"length,omitempty"`
	Description string `json:"description,omitempty"`
}

// KeyAttestationRequiredError reports that RequestCredential needs a key
// attestation it cannot obtain, before anything was sent. The caller has a
// key-attestation+jwt signed over HolderKeys with nonce CNonce and aud
// Audience, then calls RequestCredential again with Grant and
// CredentialRequest.KeyAttestation.
type KeyAttestationRequiredError struct {
	// Grant is the grant to present again. After a rejected nonce it names
	// the fresh c_nonce.
	Grant *IssuanceGrant
	// CNonce is the nonce claim the attestation must carry; empty when the
	// issuer has no Nonce Endpoint.
	CNonce string
	// HolderKeys are the public keys to list in attested_keys, in proof
	// order.
	HolderKeys []jose.JSONWebKey
	// Audience is the Credential Issuer Identifier.
	Audience string
	// IssuerRequired is false when the attestation was only volunteered with
	// IncludeKeyAttestation, so retrying without it is possible.
	IssuerRequired bool
	// NonceRejected reports that the supplied attestation carried another
	// nonce, or that the issuer answered invalid_nonce and issued a fresh
	// one. Attestations are single use, so a new one is needed.
	NonceRejected bool
}

// ErrorCode returns key_attestation_nonce_rejected when NonceRejected is set
// and key_attestation_required otherwise.
func (e *KeyAttestationRequiredError) ErrorCode() string {
	return e.sentinel().(CodedError).ErrorCode()
}

func (e *KeyAttestationRequiredError) sentinel() error {
	if e != nil && e.NonceRejected {
		return ErrKeyAttestationNonceRejected
	}
	return ErrKeyAttestationRequired
}

// Error implements error.
func (e *KeyAttestationRequiredError) Error() string {
	if e == nil {
		return ErrKeyAttestationRequired.Error()
	}
	return fmt.Sprintf("%s: sign a key-attestation+jwt for %d holder key(s) with nonce %q and aud %q",
		e.sentinel(), len(e.HolderKeys), e.CNonce, e.Audience)
}

// Unwrap returns ErrKeyAttestationNonceRejected or ErrKeyAttestationRequired.
func (e *KeyAttestationRequiredError) Unwrap() error { return e.sentinel() }

// AuthorizationResponseError is the RFC 6749 Section 4.1.2.1 error redirect
// the authorization server returned instead of a code. It is only reported
// after the redirect's state and iss were verified.
type AuthorizationResponseError struct {
	// Code is the error the server reported, such as access_denied.
	Code        string
	Description string
	// State is the verified state the redirect echoed.
	State string
}

// ErrorCode returns authorization_error_response; Code carries the server's
// error.
func (e *AuthorizationResponseError) ErrorCode() string {
	return "authorization_error_response"
}

// Error implements error.
func (e *AuthorizationResponseError) Error() string {
	if e == nil {
		return "authorization response error"
	}
	if e.Description == "" {
		return fmt.Sprintf("authorization response error: %s", e.Code)
	}
	return fmt.Sprintf("authorization response error: %s: %s", e.Code, e.Description)
}
