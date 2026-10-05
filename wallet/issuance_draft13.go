package wallet

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/trustknots/vcknots/wallet/acceptance"
	"github.com/trustknots/vcknots/wallet/common"
	credstoreTypes "github.com/trustknots/vcknots/wallet/credstore/types"
	"github.com/trustknots/vcknots/wallet/experimental"
	"github.com/trustknots/vcknots/wallet/profile"
	receiverOid4vci "github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// Draft13Issuance runs OpenID4VCI Draft 13 issuances with the same staged
// methods and state types as the Wallet's 1.0 methods; the states carry
// profile.Draft13 as their Profile. Differences from 1.0: an offer is
// required, the c_nonce comes from the Token Response and the Credential
// Response, one key proof is sent, and there are no key attestations or
// credential encryption.
// Every method returns ErrProfileForbidsDraft under HAIP.
type Draft13Issuance struct {
	w *Wallet
}

// Draft13 returns the OpenID4VCI Draft 13 view of the wallet.
func (w *Wallet) Draft13() *Draft13Issuance {
	return &Draft13Issuance{w: w}
}

// BeginIssuance starts a Draft 13 Authorization Code Flow (Section 3.4): it
// requires an offer with an authorization_code grant, or without grants when
// the authorization server supports that grant (Section 4.1.1), pushes the
// authorization request when the server supports PAR, and returns the state
// holding the URL to open in the holder's browser. Like the 1.0 BeginIssuance
// it sends nothing without req.Acceptance or Config.CredentialAcceptance.
func (d *Draft13Issuance) BeginIssuance(ctx context.Context, req IssuanceRequest) (*IssuanceAuthorization, error) {
	authorization, err := d.beginIssuance(ctx, req)
	return authorization, classify(err)
}

// AuthorizeIssuance exchanges the code of the redirect the holder's browser
// delivered, as the 1.0 AuthorizeIssuance does.
func (d *Draft13Issuance) AuthorizeIssuance(ctx context.Context, authorization *IssuanceAuthorization, redirectURL string) (*IssuanceGrant, error) {
	grant, err := d.authorizeIssuance(ctx, authorization, redirectURL)
	return grant, classify(err)
}

// AuthorizePreAuthorizedIssuance runs the Draft 13 Pre-Authorized Code Flow
// token request (Section 6.1). Like the 1.0 method it does not redeem the
// code without req.Acceptance or Config.CredentialAcceptance, and the grant
// carries req.Acceptance to RequestCredential.
func (d *Draft13Issuance) AuthorizePreAuthorizedIssuance(ctx context.Context, req PreAuthorizedIssuanceRequest) (*IssuanceGrant, error) {
	grant, err := d.authorizePreAuthorizedIssuance(ctx, req)
	return grant, classify(err)
}

// RequestCredential sends the Draft 13 Credential Request (Section 7.2) with
// one key proof, retrying once with the fresh c_nonce of an invalid_proof
// error (Section 7.3.2). Config.Experimental.Hooks.KeyProof rewrites the
// proof. The credential is verified under the policy the 1.0
// RequestCredential resolves (req.Acceptance, the grant's, or
// Config.CredentialAcceptance), and saved unless the wallet is storeless.
// Without one nothing is sent (ErrCredentialAcceptancePolicyRequired).
func (d *Draft13Issuance) RequestCredential(ctx context.Context, grant *IssuanceGrant, req CredentialRequest) (*IssuanceResult, error) {
	result, err := d.requestCredential(ctx, grant, req)
	return result, classify(err)
}

// draft13DefaultPendingInterval is the wait, in seconds, of an
// issuance_pending error that names no interval (Draft 13 Section 9.3).
const draft13DefaultPendingInterval = 5

// RequestDeferredCredential sends one Draft 13 Deferred Credential Request
// (Section 9). While the issuer answers issuance_pending, the result's
// Deferred carries the interval it named, or the Section 9.3 default of five
// seconds. The library never shortens the issuer's interval.
func (d *Draft13Issuance) RequestDeferredCredential(ctx context.Context, deferred *DeferredIssuance) (*IssuanceResult, error) {
	result, err := d.requestDeferredCredential(ctx, deferred)
	return result, classify(err)
}

// NotifyIssuer sends one Draft 13 Notification Request (Section 10.1). The
// issuer's refusal is a *receiverTypes.Draft13CredentialEndpointError.
func (d *Draft13Issuance) NotifyIssuer(ctx context.Context, n *IssuanceNotification, event NotificationEvent, description string) error {
	return classify(d.notifyIssuer(ctx, n, event, description))
}

// require applies the preconditions of every Draft 13 stage.
func (d *Draft13Issuance) require(ctx context.Context) (receiverTypes.Draft13Transport, error) {
	w := d.w
	if err := w.requireDraft13(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	transport, err := w.receiver.Draft13Transport(receiverTypes.Oid4vci)
	if err != nil {
		return nil, fmt.Errorf("OpenID4VCI Draft 13 transport capability is not available: %w", err)
	}
	return transport, nil
}

// checkOfferIssuer applies the Credential Issuer Identifier rules to the
// offer's issuer, with plain http only where the receiver allows it.
func (d *Draft13Issuance) checkOfferIssuer(transport receiverTypes.Draft13Transport, offer *CredentialOffer) error {
	if offer == nil {
		return ErrDraft13OfferMissing
	}
	allowHTTP := false
	if policy, ok := transport.(receiverTypes.HTTPSchemePolicy); ok {
		allowHTTP = policy.HTTPAllowed()
	}
	if err := validateCredentialIssuerIdentifier(offer.CredentialIssuer, allowHTTP); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidArgument, err)
	}
	return nil
}

// draft13Discovery resolves Credential Issuer Metadata at the Draft 13
// Section 11.2.2 location for discoverIssuance; the OpenID4VCI 1.0 Section
// 12.2.2 location is never tried for a Draft 13 issuance.
type draft13Discovery struct {
	receiverTypes.Draft13Transport
}

// DiscoverCredentialIssuer is DiscoverDraft13CredentialIssuer.
func (d draft13Discovery) DiscoverCredentialIssuer(ctx context.Context, issuer common.URIField) (*receiverTypes.CredentialIssuerMetadata, error) {
	return d.DiscoverDraft13CredentialIssuer(ctx, issuer)
}

// discover resolves the metadata an offer points at and checks that every
// offered configuration is described.
func (d *Draft13Issuance) discover(ctx context.Context, transport receiverTypes.Draft13Transport, offer *CredentialOffer, hint string) (*issuanceDiscovery, error) {
	discovery, err := d.w.discoverIssuance(ctx, draft13Discovery{transport}, nil, offer.CredentialIssuer.String(), offeredAuthorizationServer(hint), true)
	if err != nil {
		return nil, err
	}
	if err := validateOfferedConfigurations(offer, discovery.issuerMetadata); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDraft13CredentialConfigurationUnknown, err)
	}
	if discovery.asMetadata.TokenEndpoint == nil {
		return nil, ErrDraft13TokenEndpointMissing
	}
	return discovery, nil
}

// selectConfiguration returns the requested offered configuration, or the
// first the offer lists.
func selectDraft13Configuration(offer *CredentialOffer, requested string, md *receiverTypes.CredentialIssuerMetadata) (string, receiverTypes.CredentialConfiguration, error) {
	id := strings.TrimSpace(requested)
	switch {
	case id == "" && len(offer.CredentialConfigurationIDs) == 0:
		return "", receiverTypes.CredentialConfiguration{}, invalidArgument("credential configuration IDs are empty")
	case id == "":
		id = offer.CredentialConfigurationIDs[0]
	default:
		offered := false
		for _, candidate := range offer.CredentialConfigurationIDs {
			offered = offered || candidate == id
		}
		if !offered {
			return "", receiverTypes.CredentialConfiguration{}, fmt.Errorf("credential configuration %q is not one the offer lists: %w", id, ErrDraft13CredentialConfigurationUnknown)
		}
	}
	config, ok := md.CredentialConfigurationSupported[id]
	if !ok {
		return "", receiverTypes.CredentialConfiguration{}, fmt.Errorf("credential configuration %q: %w", id, ErrDraft13CredentialConfigurationUnknown)
	}
	// Draft 13 Appendix A: a format outside the Draft 13 table is refused
	// before any request.
	if _, err := receiverOid4vci.CredentialFormatFlavor(profile.Draft13(), config.Format); err != nil {
		return "", receiverTypes.CredentialConfiguration{}, fmt.Errorf("credential configuration %q: %w", id, err)
	}
	return id, config, nil
}

// dpopEnabled reports whether a Draft 13 token request carries DPoP: the
// wallet holds a key and the server advertises dpop_signing_alg_values_supported
// (RFC 9449 Section 5.1), or DPoPConfig.Enabled forces it.
func (d *Draft13Issuance) dpopEnabled(as *receiverTypes.AuthorizationServerMetadata) bool {
	w := d.w
	if w.dpop.Key == nil {
		return false
	}
	if w.dpop.Enabled {
		return true
	}
	return as != nil && as.DPoPSigningAlgValuesSupported != nil && len(*as.DPoPSigningAlgValuesSupported) > 0
}

// tokenAuthentication is the DPoP and client authentication of a Draft 13
// token or PAR request. The configured method is used as configured, never
// downgraded: private_key_jwt needs the server to advertise it, and none
// needs a server that lists none, publishes no
// token_endpoint_auth_methods_supported (Draft 13 predates the negotiation),
// or declares pre-authorized_grant_anonymous_access_supported. Anything else
// is refused with errNoUsableClientAuthMethod before the request is sent, as
// the OpenID4VCI 1.0 negotiation refuses it.
func (d *Draft13Issuance) tokenAuthentication(ctx context.Context, as *receiverTypes.AuthorizationServerMetadata, dpop bool) (receiverTypes.ClientAuthentication, error) {
	w := d.w
	var auth receiverTypes.ClientAuthentication
	switch method := w.clientAuth.Method; method {
	case receiverTypes.PrivateKeyJwt:
		if err := clientAuthMethodUsable(method, w.clientAuth, as); err != nil {
			return auth, err
		}
		auth.ClientAssertion = w.privateKeyJWTFactory(ctx, as)
	case "", receiverTypes.None:
		if as.TokenEndpointAuthMethodsSupported != nil && !anonymousPreAuthorizedAccessSupported(as) {
			if err := clientAuthMethodUsable(receiverTypes.None, w.clientAuth, as); err != nil {
				return auth, err
			}
		}
	default:
		return auth, unimplementedAuthMethodError(method)
	}
	if dpop && d.dpopEnabled(as) {
		auth.DPoP = dpopProofFactory(ctx, w.dpop.Key, http.MethodPost, as.TokenEndpoint.String(), "")
	}
	return auth, nil
}

func (d *Draft13Issuance) beginIssuance(ctx context.Context, req IssuanceRequest) (*IssuanceAuthorization, error) {
	transport, err := d.require(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := d.w.acceptancePolicy(req.Acceptance); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.CredentialIssuer) != "" {
		return nil, invalidArgument("Draft 13 starts from a credential offer; CredentialIssuer must be empty")
	}
	if err := d.checkOfferIssuer(transport, req.CredentialOffer); err != nil {
		return nil, err
	}
	grant, grantFromMetadata := offerGrant(req.CredentialOffer, string(receiverTypes.AuthorizationCode))
	if grant == nil {
		return nil, ErrDraft13AuthorizationCodeGrantMissing
	}
	clientID, redirectURI, err := d.w.authorizationCodeClient()
	if err != nil {
		return nil, err
	}
	discovery, err := d.discover(ctx, transport, req.CredentialOffer, strings.TrimSpace(grant.AuthorizationServer))
	if err != nil {
		return nil, err
	}
	md, as := discovery.issuerMetadata, discovery.asMetadata
	if as.AuthorizationEndpoint == nil {
		return nil, ErrDraft13AuthorizationEndpointMissing
	}
	if err := requireSecureAuthorizationEndpoint(transport, as.AuthorizationEndpoint); err != nil {
		return nil, err
	}
	if err := checkOfferedAuthorizationCodeGrant(grantFromMetadata, as); err != nil {
		return nil, err
	}
	configurationID, config, err := selectDraft13Configuration(req.CredentialOffer, req.CredentialConfigurationID, md)
	if err != nil {
		return nil, err
	}
	scope, details, err := authorizationRequestParameters(req.AuthorizationRequestType, configurationID, config, false)
	if err != nil {
		return nil, err
	}
	setAuthorizationDetailLocations(details, md)
	verifier, challenge, state, err := newPKCE()
	if err != nil {
		return nil, err
	}
	request := receiverTypes.PushedAuthorizationRequest{
		ResponseType:         "code",
		ClientID:             clientID,
		RedirectURI:          redirectURI,
		Scope:                scope,
		AuthorizationDetails: details,
		State:                state,
		CodeChallenge:        challenge,
		CodeChallengeMethod:  "S256",
		IssuerState:          grant.IssuerState,
	}
	authorization := &IssuanceAuthorization{
		Profile:                       profile.Draft13(),
		State:                         state,
		CodeVerifier:                  verifier,
		CredentialIssuer:              md.CredentialIssuer,
		CredentialConfigurationID:     configurationID,
		AuthorizationServer:           discovery.authorizationServer,
		ClientID:                      clientID,
		RedirectURI:                   redirectURI,
		AuthorizationDetailsRequested: len(details) > 0,
		Acceptance:                    req.Acceptance,
		AcceptanceOverridden:          req.Acceptance != nil,
	}
	usePAR, err := pushedAuthorizationRequired(as, false)
	if err != nil {
		return nil, err
	}
	requestURI := ""
	if usePAR {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		auth, err := d.tokenAuthentication(ctx, as, false)
		if err != nil {
			return nil, err
		}
		pushed, err := transport.PushAuthorizationRequest(ctx, *as.PushedAuthorizationRequestEndpoint, request, auth)
		if requestURI, err = acceptPushedAuthorization(authorization, pushed, err); err != nil {
			return nil, err
		}
	}
	authorization.AuthorizationURL = authorizationRequestURL(as.AuthorizationEndpoint, clientID, request, requestURI)
	if requestURI == "" && len(md.AuthorizationServers) > 0 {
		// Section 5.1.2 recommends the RFC 8707 resource indicator when the
		// issuer delegates to authorization_servers.
		parsed, err := url.Parse(authorization.AuthorizationURL)
		if err != nil {
			return nil, fmt.Errorf("failed to parse the authorization request URL: %w", err)
		}
		query := parsed.Query()
		query.Set("resource", md.CredentialIssuer)
		parsed.RawQuery = query.Encode()
		authorization.AuthorizationURL = parsed.String()
	}
	authorization.cache = d.w.newIssuanceMetadataCache(discovery)
	return authorization, nil
}

func (d *Draft13Issuance) authorizeIssuance(ctx context.Context, a *IssuanceAuthorization, redirectURL string) (*IssuanceGrant, error) {
	transport, err := d.require(ctx)
	if err != nil {
		return nil, err
	}
	if err := d.w.checkAuthorizationState(a, profile.Draft13()); err != nil {
		return nil, err
	}
	if _, err := d.w.authorizationAcceptancePolicy(a); err != nil {
		return nil, err
	}
	discovery, err := d.w.discoverIssuance(ctx, draft13Discovery{transport}, a.cache, a.CredentialIssuer, pinnedAuthorizationServer(a.AuthorizationServer), true)
	if err != nil {
		return nil, err
	}
	as := discovery.asMetadata
	if as.TokenEndpoint == nil {
		return nil, ErrDraft13TokenEndpointMissing
	}
	if _, ok := discovery.issuerMetadata.CredentialConfigurationSupported[a.CredentialConfigurationID]; !ok {
		return nil, fmt.Errorf("credential configuration %q: %w", a.CredentialConfigurationID, ErrDraft13CredentialConfigurationUnknown)
	}
	advertised := as.AuthorizationResponseIssParameterSupported
	code, err := validateAuthorizationRedirect(redirectURL, a.AuthorizationURL, a.State, a.RedirectURI, authorizationResponseIssuerPolicy{
		expected: discovery.authorizationServer,
		required: advertised != nil && *advertised,
	})
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	auth, err := d.tokenAuthentication(ctx, as, true)
	if err != nil {
		return nil, err
	}
	token, err := transport.RequestToken(ctx, *as.TokenEndpoint, receiverTypes.TokenRequest{
		GrantType:    receiverTypes.AuthorizationCode,
		Code:         code,
		RedirectURI:  a.RedirectURI,
		CodeVerifier: a.CodeVerifier,
		ClientID:     a.ClientID,
	}, auth)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange authorization code: %w", err)
	}
	mode := authorizationDetailsOptional
	if a.AuthorizationDetailsRequested {
		mode = authorizationDetailsEntryRequired
	}
	grant, err := d.newGrant(discovery, a.CredentialConfigurationID, token, mode)
	if err != nil {
		return nil, err
	}
	return grant.carryAcceptance(a.Acceptance), nil
}

func (d *Draft13Issuance) authorizePreAuthorizedIssuance(ctx context.Context, req PreAuthorizedIssuanceRequest) (*IssuanceGrant, error) {
	transport, err := d.require(ctx)
	if err != nil {
		return nil, err
	}
	// The pre-authorized code is used once (Section 4.1.1), so it is not
	// redeemed for a credential the wallet could not accept.
	if _, err := d.w.acceptancePolicy(req.Acceptance); err != nil {
		return nil, err
	}
	if err := d.checkOfferIssuer(transport, req.CredentialOffer); err != nil {
		return nil, err
	}
	grant := req.CredentialOffer.Grants[string(receiverTypes.PreAuthorizedCode)]
	if grant == nil || strings.TrimSpace(grant.PreAuthorizedCode) == "" {
		return nil, ErrDraft13PreAuthorizedCodeGrantMissing
	}
	// Section 6.1: tx_code "MUST be present if a tx_code object was present
	// in the Credential Offer (including if the object was empty)", as in 1.0.
	if err := checkTxCode(grant, req.TxCode); err != nil {
		return nil, err
	}
	hint := strings.TrimSpace(req.AuthorizationServer)
	if hint == "" {
		hint = strings.TrimSpace(grant.AuthorizationServer)
	}
	discovery, err := d.discover(ctx, transport, req.CredentialOffer, hint)
	if err != nil {
		return nil, err
	}
	configurationID, _, err := selectDraft13Configuration(req.CredentialOffer, req.CredentialConfigurationID, discovery.issuerMetadata)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	as := discovery.asMetadata
	// Section 6.1 makes client_id OPTIONAL for this grant; it is sent when
	// Config names one. Without one the request is anonymous, which Section
	// 11.3 allows only when the server declares
	// pre-authorized_grant_anonymous_access_supported true.
	clientID := strings.TrimSpace(d.w.clientAuth.ClientID)
	if clientID == "" && !anonymousPreAuthorizedAccessSupported(as) {
		return nil, errNoUsableClientAuthMethod
	}
	auth, err := d.tokenAuthentication(ctx, as, true)
	if err != nil {
		return nil, err
	}
	token, err := transport.RequestToken(ctx, *as.TokenEndpoint, receiverTypes.TokenRequest{
		GrantType:         receiverTypes.PreAuthorizedCode,
		PreAuthorizedCode: grant.PreAuthorizedCode,
		TxCode:            req.TxCode,
		ClientID:          clientID,
	}, auth)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch access token: %w", err)
	}
	issuanceGrant, err := d.newGrant(discovery, configurationID, token, authorizationDetailsOptional)
	if err != nil {
		return nil, err
	}
	return issuanceGrant.carryAcceptance(req.Acceptance), nil
}

// newGrant collects the Token Response into a Draft 13 grant; its c_nonce is
// the Token Response's (Draft 13 Section 6.2).
func (d *Draft13Issuance) newGrant(discovery *issuanceDiscovery, configurationID string, token *receiverTypes.CredentialIssuanceAccessToken, mode authorizationDetailsMode) (*IssuanceGrant, error) {
	// RFC 6749 Sections 5.1 and 7.1: token_type is REQUIRED, and a client
	// "MUST NOT use an access token if it does not understand the token
	// type"; the wallet presents Bearer (RFC 6750) and DPoP (RFC 9449).
	if err := d.w.checkTokenType(token); err != nil {
		return nil, err
	}
	identifiers, err := credentialIdentifiersFor(token, configurationID, mode)
	if err != nil {
		if mode != authorizationDetailsOptional {
			return nil, err
		}
		// Authorization details for another configuration do not stop a
		// request that can name the configuration itself.
		identifiers = nil
	}
	grant := &IssuanceGrant{
		Profile:                   profile.Draft13(),
		CredentialIssuer:          discovery.issuerMetadata.CredentialIssuer,
		CredentialConfigurationID: configurationID,
		AuthorizationServer:       discovery.authorizationServer,
		AccessToken:               token,
		CredentialIdentifiers:     identifiers,
		cache:                     d.w.newIssuanceMetadataCache(discovery),
	}
	if token.CNonce != nil {
		grant.CNonce = *token.CNonce
	}
	if isDPoPAccessToken(token) {
		if grant.DPoPKeyThumbprint, err = keyThumbprint(d.w.dpop.Key); err != nil {
			return nil, fmt.Errorf("failed to compute the DPoP key thumbprint: %w", err)
		}
	}
	return grant, nil
}

// credentialStage is what the Draft 13 credential, deferred and notification
// requests share: the transport, the re-discovered metadata and the DPoP key
// a DPoP-bound token needs.
func (d *Draft13Issuance) credentialStage(ctx context.Context, cache *issuanceMetadataCache, issuer string, token *receiverTypes.CredentialIssuanceAccessToken, thumbprint string, missingKey error) (receiverTypes.Draft13Transport, *issuanceDiscovery, IKeyEntry, error) {
	transport, err := d.require(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	if token == nil || strings.TrimSpace(token.Token) == "" {
		return nil, nil, nil, fmt.Errorf("the state carries no access token: %w", ErrIssuanceStateMismatch)
	}
	dpopKey, err := d.w.requireDPoPKey(thumbprint, token, missingKey)
	if err != nil {
		return nil, nil, nil, err
	}
	discovery, err := d.w.discoverIssuance(ctx, draft13Discovery{transport}, cache, issuer, offeredAuthorizationServer(""), false)
	if err != nil {
		return nil, nil, nil, err
	}
	return transport, discovery, dpopKey, nil
}

func (d *Draft13Issuance) requestCredential(ctx context.Context, grant *IssuanceGrant, req CredentialRequest) (*IssuanceResult, error) {
	if err := d.w.requireDraft13(); err != nil {
		return nil, err
	}
	if err := checkGrant(grant, profile.Draft13()); err != nil {
		return nil, err
	}
	if len(req.HolderKeys) > 1 {
		return nil, invalidArgument("Draft 13 sends one key proof; %d holder keys were given", len(req.HolderKeys))
	}
	if req.KeyAttestation != nil || req.IncludeKeyAttestation {
		return nil, invalidArgument("Draft 13 has no key attestation")
	}
	policy, perRequest, err := d.w.grantAcceptancePolicy(grant, req.Acceptance)
	if err != nil {
		return nil, err
	}
	var holderKey IKeyEntry
	if len(req.HolderKeys) == 1 {
		if holderKey = req.HolderKeys[0]; holderKey == nil {
			return nil, invalidArgument("holder key 0 is nil")
		}
	}
	transport, discovery, dpopKey, err := d.credentialStage(ctx, grant.cache, grant.CredentialIssuer, grant.AccessToken, grant.DPoPKeyThumbprint,
		fmt.Errorf("dpop key is required for a DPoP-bound access token: %w", ErrDPoPKeyMismatch))
	if err != nil {
		return nil, err
	}
	md := discovery.issuerMetadata
	config, ok := md.CredentialConfigurationSupported[grant.CredentialConfigurationID]
	if !ok {
		return nil, fmt.Errorf("credential configuration %q: %w", grant.CredentialConfigurationID, ErrDraft13CredentialConfigurationUnknown)
	}
	endpoint := md.CredentialEndpoint
	if endpoint.String() == "" {
		return nil, ErrDraft13CredentialEndpointMissing
	}
	identifier, err := selectCredentialIdentifier(grant, req.CredentialIdentifier)
	if err != nil {
		return nil, err
	}
	token := *grant.AccessToken
	dpop := dpopProofFactory(ctx, dpopKey, http.MethodPost, endpoint.String(), token.Token)
	post := func(nonce string) (*receiverTypes.Draft13CredentialResponse, error) {
		request, err := d.credentialRequest(ctx, md, config, identifier, holderKey, nonce)
		if err != nil {
			return nil, err
		}
		return transport.RequestDraft13Credential(ctx, endpoint, token, *request, dpop)
	}
	nonce := grant.CNonce
	response, err := post(nonce)
	var endpointError *receiverTypes.Draft13CredentialEndpointError
	// Section 7.3.2: invalid_proof carries a fresh c_nonce; retry once.
	if err != nil && errors.As(err, &endpointError) && endpointError.Code == "invalid_proof" && endpointError.CNonce != "" && endpointError.CNonce != nonce {
		response, err = post(endpointError.CNonce)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to receive credential: %w", err)
	}
	var holderKeys []jose.JSONWebKey
	if holderKey != nil {
		holderKeys = publicKeys([]IKeyEntry{holderKey})
	}
	if response.Credential == "" {
		if response.TransactionID == "" {
			return nil, ErrDraft13CredentialResponseInvalid
		}
		if md.DeferredCredentialEndpoint == nil {
			return nil, ErrDraft13DeferredEndpointMissing
		}
		return &IssuanceResult{
			CredentialResponse: draft13CredentialResponse(response),
			Deferred: &DeferredIssuance{
				Profile:                   profile.Draft13(),
				CredentialIssuer:          md.CredentialIssuer,
				CredentialConfigurationID: grant.CredentialConfigurationID,
				TransactionID:             response.TransactionID,
				AccessToken:               grant.AccessToken,
				Interval:                  intervalDuration(response.Interval),
				HolderKeys:                holderKeys,
				DPoPKeyThumbprint:         grant.DPoPKeyThumbprint,
				Acceptance:                perRequest,
				AcceptanceOverridden:      perRequest != nil,
				cache:                     d.w.newIssuanceMetadataCache(discovery),
			},
		}, nil
	}
	return d.acceptCredential(ctx, policy, md, config, grant.AccessToken, grant.DPoPKeyThumbprint, response, holderKeys)
}

// credentialRequest builds the Section 7.2 Credential Request with a key
// proof for nonce when the configuration asks for one.
func (d *Draft13Issuance) credentialRequest(ctx context.Context, md *receiverTypes.CredentialIssuerMetadata, config receiverTypes.CredentialConfiguration, identifier string, key IKeyEntry, nonce string) (*receiverTypes.Draft13CredentialRequest, error) {
	request := &receiverTypes.Draft13CredentialRequest{}
	if identifier != "" {
		// Section 7.2: credential_identifier and format are exclusive.
		request.CredentialIdentifier = identifier
	} else {
		request.Format = config.Format
		request.VCT = config.VCT
		// Appendix A.1.1.5: a jwt_vc_json request names the credential type;
		// A.1.2.5: an ldp_vc request also names its @context.
		if definition := config.CredentialDefinition; definition != nil && len(definition.Type) > 0 {
			request.CredentialDefinition = &receiverTypes.CredentialDefinition{Type: append([]string(nil), definition.Type...)}
			if config.Format == "ldp_vc" {
				request.CredentialDefinition.Context = append([]any(nil), definition.Context...)
			}
		}
	}
	if key == nil && !draft13ProofRequired(config) {
		return request, nil
	}
	if err := ensureJWTProofSupported(&config); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProofTypeUnsupported, err)
	}
	if key == nil {
		return nil, ErrDraft13HolderKeyMissing
	}
	binding, err := resolveCredentialRequestProofBindingMethod(&config)
	if err != nil {
		return nil, err
	}
	keyID := ""
	if binding == credentialRequestProofBindingMethodKID {
		did, err := d.w.GenerateDID(DIDCreateOptions{TypeID: "did:key", PublicKey: key.PublicKey()})
		if err != nil {
			return nil, fmt.Errorf("failed to generate DID: %w: %w", ErrInvalidArgument, err)
		}
		if keyID, err = didKeyVerificationMethod(did); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidArgument, err)
		}
	}
	var noncePointer, clientID *string
	if nonce != "" {
		noncePointer = &nonce
	}
	// Section 7.2.1.1: iss is the client_id, omitted by an anonymous client.
	if id := strings.TrimSpace(d.w.clientAuth.ClientID); id != "" {
		clientID = &id
	}
	var transform experimental.ProofTransform
	if d.w.testHooks != nil {
		transform = d.w.testHooks.KeyProof
	}
	proof, err := d.w.generateJWTProofWithTransform(ctx, key, keyID, noncePointer, md.CredentialIssuer, clientID, binding, transform)
	if err != nil {
		return nil, err
	}
	request.Proof = &receiverTypes.Draft13Proof{ProofType: "jwt", JWT: proof}
	return request, nil
}

// acceptCredential verifies and stores a Draft 13 credential; on refusal the
// result carries the notification for credential_failure.
func (d *Draft13Issuance) acceptCredential(ctx context.Context, policy *acceptance.Policy, md *receiverTypes.CredentialIssuerMetadata, config receiverTypes.CredentialConfiguration, token *receiverTypes.CredentialIssuanceAccessToken, thumbprint string, response *receiverTypes.Draft13CredentialResponse, holderKeys []jose.JSONWebKey) (*IssuanceResult, error) {
	result := &IssuanceResult{CredentialResponse: draft13CredentialResponse(response)}
	if response.NotificationID != "" {
		result.Notification = &IssuanceNotification{
			Profile:           profile.Draft13(),
			CredentialIssuer:  md.CredentialIssuer,
			NotificationID:    response.NotificationID,
			AccessToken:       token,
			DPoPKeyThumbprint: thumbprint,
		}
	}
	flavor, err := receiverOid4vci.CredentialFormatFlavor(profile.Draft13(), config.Format)
	if err != nil {
		return result, fmt.Errorf("unsupported credential format %q: %w: %w", config.Format, acceptance.ErrCredentialParse, err)
	}
	raw := []byte(response.Credential)
	// The same binding rule as the 1.0 path: a configuration that lists
	// binding methods requires a cnf, and a cnf must name the holder key.
	holderKey, err := matchBatchHolderKey(raw, flavor, holderKeys, make([]bool, len(holderKeys)), configurationRequiresBinding(config))
	if err != nil {
		return result, err
	}
	parsed, verification, err := d.w.verifyCredentialUnder(ctx, profile.Draft13(), policy, raw, flavor, holderKey, md.CredentialIssuer)
	if err != nil {
		return result, fmt.Errorf("failed to verify credential: %w", err)
	}
	saved := &SavedCredential{
		Credential:   parsed,
		Entry:        &credstoreTypes.CredentialEntry{Id: uuid.New().String(), ReceivedAt: time.Now(), Raw: raw, MimeType: string(flavor)},
		Verification: verification,
	}
	if err := d.w.saveCredentials([]*SavedCredential{saved}); err != nil {
		return result, err
	}
	result.Credentials = []*SavedCredential{saved}
	return result, nil
}

// draft13CredentialResponse reports a Draft 13 response in the 1.0 shape.
func draft13CredentialResponse(response *receiverTypes.Draft13CredentialResponse) *receiverTypes.CredentialResponse {
	converted := &receiverTypes.CredentialResponse{
		TransactionID:  response.TransactionID,
		NotificationID: response.NotificationID,
		Interval:       response.Interval,
	}
	if response.Credential != "" {
		converted.Credentials = []any{map[string]any{"credential": response.Credential}}
	}
	if response.CNonce != "" {
		nonce := response.CNonce
		converted.CNonce = &nonce
	}
	return converted
}

func (d *Draft13Issuance) requestDeferredCredential(ctx context.Context, deferred *DeferredIssuance) (*IssuanceResult, error) {
	if err := d.w.requireDraft13(); err != nil {
		return nil, err
	}
	if err := checkDeferred(deferred, profile.Draft13()); err != nil {
		return nil, err
	}
	policy, err := d.w.deferredAcceptancePolicy(deferred)
	if err != nil {
		return nil, err
	}
	transport, discovery, dpopKey, err := d.credentialStage(ctx, deferred.cache, deferred.CredentialIssuer, deferred.AccessToken, deferred.DPoPKeyThumbprint,
		fmt.Errorf("dpop key is required for a DPoP-bound access token: %w", ErrDPoPKeyMismatch))
	if err != nil {
		return nil, err
	}
	md := discovery.issuerMetadata
	config, ok := md.CredentialConfigurationSupported[deferred.CredentialConfigurationID]
	if !ok {
		return nil, fmt.Errorf("credential configuration %q: %w", deferred.CredentialConfigurationID, ErrDraft13CredentialConfigurationUnknown)
	}
	endpoint := md.DeferredCredentialEndpoint
	if endpoint == nil || endpoint.String() == "" {
		return nil, ErrDraft13DeferredEndpointMissing
	}
	response, err := transport.RequestDraft13DeferredCredential(ctx, *endpoint, *deferred.AccessToken, deferred.TransactionID,
		dpopProofFactory(ctx, dpopKey, http.MethodPost, endpoint.String(), deferred.AccessToken.Token))
	if err != nil {
		var endpointError *receiverTypes.Draft13CredentialEndpointError
		if errors.As(err, &endpointError) && errors.Is(endpointError, receiverTypes.ErrDraft13IssuancePending) {
			interval := endpointError.Interval
			if interval <= 0 {
				// Section 9.3: "If interval member is not present, the Wallet
				// MUST use 5 as the default value."
				interval = draft13DefaultPendingInterval
			}
			return pendingDeferred(deferred, d.w, discovery, interval), nil
		}
		return nil, fmt.Errorf("deferred credential request failed: %w", err)
	}
	if response.Credential == "" {
		// Section 9.1: "still pending" is the Section 9.2 error, not a body.
		return nil, ErrDraft13CredentialResponseInvalid
	}
	return d.acceptCredential(ctx, policy, md, config, deferred.AccessToken, deferred.DPoPKeyThumbprint, response, deferred.HolderKeys)
}

func (d *Draft13Issuance) notifyIssuer(ctx context.Context, n *IssuanceNotification, event NotificationEvent, description string) error {
	if err := d.w.requireDraft13(); err != nil {
		return err
	}
	if err := checkNotification(n, profile.Draft13(), event, description); err != nil {
		return err
	}
	transport, discovery, dpopKey, err := d.credentialStage(ctx, nil, n.CredentialIssuer, n.AccessToken, n.DPoPKeyThumbprint, ErrNotificationDPoPKeyMissing)
	if err != nil {
		return err
	}
	endpoint := discovery.issuerMetadata.NotificationEndpoint
	if endpoint == nil || endpoint.String() == "" {
		return ErrDraft13NotificationEndpointMissing
	}
	return transport.SendDraft13Notification(ctx, *endpoint, *n.AccessToken, receiverTypes.NotificationRequest{
		NotificationID:   n.NotificationID,
		Event:            string(event),
		EventDescription: description,
	}, dpopProofFactory(ctx, dpopKey, http.MethodPost, endpoint.String(), n.AccessToken.Token))
}
