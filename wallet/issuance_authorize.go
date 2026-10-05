package wallet

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/profile"
	receiverOid4vci "github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// BeginIssuance starts an OpenID4VCI 1.0 Authorization Code Flow: it resolves
// the issuer and authorization server metadata, checks the configuration
// against the wallet profile and Config.Issuance.CredentialEncryption, pushes
// the authorization request when the server supports RFC 9126 PAR (HAIP
// requires it), and returns the state holding the URL to open in the holder's
// browser. The library does not open it. Config.ClientAuth.ClientID and
// Config.Issuance.RedirectURI identify the wallet. Without req.Acceptance or
// Config.CredentialAcceptance nothing is sent
// (ErrCredentialAcceptancePolicyRequired); the state carries req.Acceptance.
func (w *Wallet) BeginIssuance(ctx context.Context, req IssuanceRequest) (*IssuanceAuthorization, error) {
	authorization, err := w.beginIssuance(ctx, req)
	return authorization, classify(err)
}

func (w *Wallet) beginIssuance(ctx context.Context, req IssuanceRequest) (*IssuanceAuthorization, error) {
	if err := w.requireFinalAuthorizationStage(ctx); err != nil {
		return nil, err
	}
	if _, err := w.acceptancePolicy(req.Acceptance); err != nil {
		return nil, err
	}
	clientID, redirectURI, err := w.authorizationCodeClient()
	if err != nil {
		return nil, err
	}
	var issuer, configurationID, issuerState, hint string
	grantFromMetadata := false
	if req.CredentialOffer != nil {
		if strings.TrimSpace(req.CredentialIssuer) != "" {
			return nil, invalidArgument("credential issuer must be empty when a credential offer is provided")
		}
		offered, err := fromOffer(req.CredentialOffer, req.CredentialConfigurationID, "authorization_code",
			invalidArgument("authorization_code grant is not included in the offer"))
		if err != nil {
			return nil, err
		}
		issuer, configurationID = offered.issuer, offered.configurationID
		issuerState, hint = offered.grant.IssuerState, strings.TrimSpace(offered.grant.AuthorizationServer)
		grantFromMetadata = offered.grantFromMetadata
	} else {
		// OpenID4VCI 1.0 Section 5: a wallet-initiated issuance names the
		// issuer and the configuration itself.
		issuer, configurationID = strings.TrimSpace(req.CredentialIssuer), strings.TrimSpace(req.CredentialConfigurationID)
		if issuer == "" {
			return nil, invalidArgument("credential issuer is required")
		}
		if configurationID == "" {
			return nil, invalidArgument("credential configuration ID is required")
		}
	}

	transport, err := w.oid4vciTransport()
	if err != nil {
		return nil, err
	}
	discovery, err := w.discoverIssuance(ctx, transport, nil, issuer, offeredAuthorizationServer(hint), true)
	if err != nil {
		return nil, err
	}
	md, as := discovery.issuerMetadata, discovery.asMetadata
	if as.AuthorizationEndpoint == nil {
		return nil, invalidMetadata("authorization endpoint is missing on authorization server")
	}
	if err := requireSecureAuthorizationEndpoint(transport, as.AuthorizationEndpoint); err != nil {
		return nil, err
	}
	if as.TokenEndpoint == nil {
		return nil, invalidMetadata("token endpoint is missing on authorization server")
	}
	if err := checkOfferedAuthorizationCodeGrant(grantFromMetadata, as); err != nil {
		return nil, err
	}
	config, err := w.finalCredentialConfiguration(transport, md, configurationID)
	if err != nil {
		return nil, err
	}
	if err := w.issuance.CredentialEncryption.validate(md); err != nil {
		return nil, err
	}
	if err := w.checkPrivateKeyJWT(as); err != nil {
		return nil, err
	}
	usePAR, err := pushedAuthorizationRequired(as, w.options().RequirePAR)
	if err != nil {
		return nil, err
	}
	scope, details, err := authorizationRequestParameters(req.AuthorizationRequestType, configurationID, config, w.options().RequireScopeAuthorization)
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
		IssuerState:          issuerState,
	}
	authorization := &IssuanceAuthorization{
		Profile:                       w.profile,
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
	requestURI := ""
	if usePAR {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// RFC 9126 Section 2: the PAR endpoint authenticates the client like
		// the token endpoint (HAIP Section 4.4.1).
		instanceKey, err := w.flowClientInstanceKey(authorization, nil)
		if err != nil {
			return nil, err
		}
		auth, _, err := w.clientAuthentication(ctx, transport, discovery, false, instanceKey)
		if err != nil {
			return nil, err
		}
		pushed, err := transport.PushAuthorizationRequest(ctx, *as.PushedAuthorizationRequestEndpoint, request, auth)
		if requestURI, err = acceptPushedAuthorization(authorization, pushed, err); err != nil {
			return nil, err
		}
	}
	authorization.AuthorizationURL = authorizationRequestURL(as.AuthorizationEndpoint, clientID, request, requestURI)
	authorization.cache = w.newIssuanceMetadataCache(discovery)
	return authorization, nil
}

// AuthorizeIssuance completes the authorization of a Begin/IssuanceAuthorization
// pair with the redirect the holder's browser delivered: it re-discovers the
// metadata, checks the redirect (RFC 6749 Section 4.1.2, RFC 9207), exchanges
// the code at the token endpoint and fetches the c_nonce. redirectURL is the
// whole callback URL. An error redirect is returned as
// *AuthorizationResponseError. The code is not exchanged when no acceptance
// policy applies: the state's Acceptance, which a state that records one
// (AcceptanceOverridden) needs set again after serialization, or else
// Config.CredentialAcceptance (ErrCredentialAcceptancePolicyRequired).
func (w *Wallet) AuthorizeIssuance(ctx context.Context, authorization *IssuanceAuthorization, redirectURL string) (*IssuanceGrant, error) {
	grant, err := w.authorizeIssuance(ctx, authorization, redirectURL)
	return grant, classify(err)
}

func (w *Wallet) authorizeIssuance(ctx context.Context, a *IssuanceAuthorization, redirectURL string) (*IssuanceGrant, error) {
	if err := w.checkAuthorizationState(a, w.profile); err != nil {
		return nil, err
	}
	if err := w.requireFinalAuthorizationStage(ctx); err != nil {
		return nil, err
	}
	if _, err := w.authorizationAcceptancePolicy(a); err != nil {
		return nil, err
	}
	transport, err := w.oid4vciTransport()
	if err != nil {
		return nil, err
	}
	discovery, err := w.discoverIssuance(ctx, transport, a.cache, a.CredentialIssuer, pinnedAuthorizationServer(a.AuthorizationServer), true)
	if err != nil {
		return nil, err
	}
	as := discovery.asMetadata
	if as.TokenEndpoint == nil {
		return nil, invalidMetadata("token endpoint is missing on authorization server")
	}
	config, err := w.finalCredentialConfiguration(transport, discovery.issuerMetadata, a.CredentialConfigurationID)
	if err != nil {
		return nil, err
	}
	if err := w.checkPrivateKeyJWT(as); err != nil {
		return nil, err
	}
	advertised := as.AuthorizationResponseIssParameterSupported
	issuerPolicy := authorizationResponseIssuerPolicy{
		expected: discovery.authorizationServer,
		required: advertised != nil && *advertised,
	}
	// FAPI 2.0 Section 5.3.2.2, which HAIP builds on, requires the check
	// even when the server does not advertise it.
	if !issuerPolicy.required && w.options().RequireAuthorizationResponseIss {
		issuerPolicy.required, issuerPolicy.option = true, "RequireAuthorizationResponseIss"
	}
	code, err := validateAuthorizationRedirect(redirectURL, a.AuthorizationURL, a.State, a.RedirectURI, issuerPolicy)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	instanceKey, err := w.flowClientInstanceKey(nil, a.ClientInstanceKey)
	if err != nil {
		return nil, err
	}
	auth, _, err := w.clientAuthentication(ctx, transport, discovery, false, instanceKey)
	if err != nil {
		return nil, err
	}
	auth.DPoP = dpopProofFactory(ctx, w.dpop.Key, http.MethodPost, as.TokenEndpoint.String(), "")
	token, err := transport.RequestToken(ctx, *as.TokenEndpoint, receiverTypes.TokenRequest{
		GrantType:    receiverTypes.AuthorizationCode,
		Code:         code,
		CodeVerifier: a.CodeVerifier,
		RedirectURI:  a.RedirectURI,
		ClientID:     a.ClientID,
	}, auth)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange authorization code: %w", err)
	}
	mode := authorizationDetailsOptional
	if a.AuthorizationDetailsRequested {
		mode = authorizationDetailsRequired
	}
	grant, err := w.newFinalGrant(ctx, transport, discovery, a.CredentialConfigurationID, config, token, mode)
	if err != nil {
		return nil, err
	}
	grant.ClientID = a.ClientID
	return grant.carryAcceptance(a.Acceptance), nil
}

// checkAuthorizationState checks that a is a complete state recorded under
// current, and was created with the wallet's client_id and redirect_uri.
func (w *Wallet) checkAuthorizationState(a *IssuanceAuthorization, current profile.Profile) error {
	if a == nil {
		return invalidArgument("authorization state is required")
	}
	if err := checkStateProfile("authorization state", a.Profile, current); err != nil {
		return err
	}
	for name, value := range map[string]string{
		"state":                       a.State,
		"code_verifier":               a.CodeVerifier,
		"credential_issuer":           a.CredentialIssuer,
		"authorization_server":        a.AuthorizationServer,
		"credential_configuration_id": a.CredentialConfigurationID,
		"client_id":                   a.ClientID,
		"redirect_uri":                a.RedirectURI,
	} {
		if value == "" {
			return fmt.Errorf("authorization state is missing %s: %w", name, ErrIssuanceStateMismatch)
		}
	}
	if a.ClientID != w.clientAuth.ClientID || a.RedirectURI != w.issuance.RedirectURI {
		return fmt.Errorf("the authorization state names another client_id or redirect_uri than Config: %w", ErrIssuanceStateMismatch)
	}
	return nil
}

// requireFinalIssuance applies the preconditions of every OpenID4VCI 1.0
// stage: a live context and under HAIP a DPoP key (HAIP Section 4). Each
// stage resolves the acceptance policy itself, since the request or the state
// it takes may bring its own.
func (w *Wallet) requireFinalIssuance(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if w.options().RequireDPoP && w.dpop.Key == nil {
		return fmt.Errorf("%w requires Config.DPoP.Key: %w", profile.Refused("RequireDPoP"), ErrDPoPKeyRequired)
	}
	return nil
}

// requireFinalAuthorizationStage is requireFinalIssuance for the stages that
// call the PAR or token endpoint, where HAIP Section 4.4.1 also requires a
// client authentication mechanism.
func (w *Wallet) requireFinalAuthorizationStage(ctx context.Context) error {
	if err := w.requireFinalIssuance(ctx); err != nil {
		return err
	}
	if w.options().RequireClientAuthentication && w.attestationSettings().Client == nil && !clientAuthenticationConfigured(w.clientAuth) {
		return invalidArgument("%w requires an OAuth2 client authentication mechanism", profile.Refused("RequireClientAuthentication"))
	}
	return nil
}

// authorizationCodeClient returns the client_id and redirect_uri of an
// Authorization Code Flow.
func (w *Wallet) authorizationCodeClient() (string, string, error) {
	clientID := strings.TrimSpace(w.clientAuth.ClientID)
	if clientID == "" {
		return "", "", invalidArgument("Config.ClientAuth.ClientID is required for the authorization code flow")
	}
	if strings.TrimSpace(w.issuance.RedirectURI) == "" {
		return "", "", invalidArgument("Config.Issuance.RedirectURI is required for the authorization code flow")
	}
	return w.clientAuth.ClientID, w.issuance.RedirectURI, nil
}

// oid4vciTransport returns the OpenID4VCI 1.0 transport of the receiver.
func (w *Wallet) oid4vciTransport() (receiverTypes.OID4VCITransport, error) {
	transport, err := w.receiver.OID4VCITransport(receiverTypes.Oid4vci)
	if err != nil {
		return nil, fmt.Errorf("OpenID4VCI 1.0 receiver capability is not available: %w", err)
	}
	return transport, nil
}

// oid4vciProfileValidator is the receiver capability that applies the
// profile's constraints to a Credential Configuration.
type oid4vciProfileValidator interface {
	ValidateCredentialConfigurationForProfile(receiverTypes.CredentialConfiguration) error
}

// finalCredentialConfiguration returns the configuration id names after
// checking it against the profile (HAIP Section 4.1) and requiring the jwt
// proof type.
func (w *Wallet) finalCredentialConfiguration(transport receiverTypes.OID4VCITransport, md *receiverTypes.CredentialIssuerMetadata, id string) (receiverTypes.CredentialConfiguration, error) {
	config, err := credentialConfiguration(md, id)
	if err != nil {
		return config, err
	}
	// OpenID4VCI 1.0 Appendix A: a format outside the 1.0 table is refused
	// before any request, not guessed.
	if _, err := receiverOid4vci.CredentialFormatFlavor(w.profile, config.Format); err != nil {
		return config, fmt.Errorf("credential configuration %q: %w", id, err)
	}
	validator, _ := transport.(oid4vciProfileValidator)
	if validatesCredentialConfigurations(w.options()) && validator == nil {
		return config, invalidArgument("the %s profile requires a receiver plugin that validates issuer metadata against the profile", w.profile)
	}
	if validator != nil {
		if err := validator.ValidateCredentialConfigurationForProfile(config); err != nil {
			return config, fmt.Errorf("credential configuration does not satisfy the wallet profile: %w", withCode(receiverTypes.ErrInvalidMetadata, err))
		}
	}
	return config, requireJWTProofType(id, config)
}

// flowClientInstanceKey resolves the Client Instance Key of one stage of a
// flow when a Client Attestation is configured, and nil otherwise. A key the
// wallet generates is recorded in authorization, when given, so the next stage
// binds the same key; recorded is the key an earlier stage kept.
func (w *Wallet) flowClientInstanceKey(authorization *IssuanceAuthorization, recorded *jose.JSONWebKey) (IKeyEntry, error) {
	if w.attestationSettings().Client == nil {
		return nil, nil
	}
	key, generated, err := w.clientInstanceKey(recorded)
	if err != nil {
		return nil, err
	}
	if authorization != nil {
		authorization.ClientInstanceKey = generated
	}
	return key, nil
}

// checkPrivateKeyJWT refuses a configured private_key_jwt the authorization
// server does not accept, unless a client attestation authenticates the
// client instead.
func (w *Wallet) checkPrivateKeyJWT(as *receiverTypes.AuthorizationServerMetadata) error {
	if w.attestationSettings().Client != nil || w.clientAuth.Method != receiverTypes.PrivateKeyJwt {
		return nil
	}
	if !asMetadataSupportsAuthMethod(as, receiverTypes.PrivateKeyJwt) {
		return invalidMetadata("authorization server metadata does not advertise the configured private_key_jwt client authentication method")
	}
	return clientAuthMethodUsable(receiverTypes.PrivateKeyJwt, w.clientAuth, as)
}

// clientAuthentication returns how the client authenticates at the PAR and
// token endpoints: a Client Attestation for instanceKey when
// Config.Attestation.Client is set, else private_key_jwt when configured.
// Attestation and private_key_jwt are alternatives. For a pre-authorized_code
// token request without an attestation, resolveClientAuthMethod negotiates the
// method against the authorization server metadata, and the second result
// reports whether the request carries client_id (OpenID4VCI 1.0 Section 12.3).
// DPoP is left to the caller.
func (w *Wallet) clientAuthentication(ctx context.Context, transport receiverTypes.AuthorizationTransport, discovery *issuanceDiscovery, preAuthorized bool, instanceKey IKeyEntry) (receiverTypes.ClientAuthentication, bool, error) {
	var auth receiverTypes.ClientAuthentication
	attestationProver, err := w.clientAttestationFactory(ctx, transport, discovery.asMetadata, discovery.authorizationServer, instanceKey)
	if err != nil {
		return auth, false, err
	}
	if attestationProver.Headers != nil {
		auth.ClientAttestation = attestationProver
		return auth, true, nil
	}
	if !preAuthorized {
		if w.clientAuth.Method == receiverTypes.PrivateKeyJwt {
			auth.ClientAssertion = w.privateKeyJWTFactory(ctx, discovery.asMetadata)
		}
		return auth, true, nil
	}
	resolved, err := resolveClientAuthMethod(w.clientAuth, discovery.asMetadata)
	if err != nil {
		return auth, false, err
	}
	if resolved.Method == receiverTypes.PrivateKeyJwt {
		auth.ClientAssertion = w.privateKeyJWTFactory(ctx, discovery.asMetadata)
	}
	return auth, resolved.SendClientID, nil
}

// authorizationRequestParameters resolves the scope or authorization_details
// that request the configuration (OpenID4VCI 1.0 Sections 5.1.1, 5.1.2). The
// default is scope when advertised, since without one "the only way to request
// the Credential is using authorization_details" (Section 12.2.4).
// scopeOnly (Options.RequireScopeAuthorization) allows scope only (HAIP
// Sections 4.2, 4.3).
func authorizationRequestParameters(requested AuthorizationRequestType, configurationID string, config receiverTypes.CredentialConfiguration, scopeOnly bool) (string, []map[string]any, error) {
	scope := strings.TrimSpace(config.Scope)
	details := []map[string]any{{
		"type":                        receiverTypes.AuthorizationDetailTypeOpenIDCredential,
		"credential_configuration_id": configurationID,
	}}
	switch AuthorizationRequestType(strings.TrimSpace(string(requested))) {
	case "":
		if scope != "" {
			return config.Scope, nil, nil
		}
		if scopeOnly {
			return "", nil, invalidMetadata("%w requires the credential configuration %q to advertise a scope", profile.Refused("RequireScopeAuthorization"), configurationID)
		}
		return "", details, nil
	case AuthorizationRequestScope:
		if scope == "" {
			if scopeOnly {
				return "", nil, invalidMetadata("%w requires the credential configuration %q to advertise a scope", profile.Refused("RequireScopeAuthorization"), configurationID)
			}
			return "", nil, invalidMetadata("authorization request type %q requires the credential configuration %q to advertise a scope", AuthorizationRequestScope, configurationID)
		}
		return config.Scope, nil, nil
	case AuthorizationRequestDetails:
		if scopeOnly {
			return "", nil, invalidArgument("%w requires the scope authorization request type", profile.Refused("RequireScopeAuthorization"))
		}
		return "", details, nil
	default:
		return "", nil, invalidArgument("unsupported authorization request type %q", requested)
	}
}

// setAuthorizationDetailLocations names the Credential Issuer in locations
// when the issuer delegates to authorization_servers (OpenID4VCI 1.0 Section
// 5.1.1).
func setAuthorizationDetailLocations(details []map[string]any, md *receiverTypes.CredentialIssuerMetadata) {
	if len(md.AuthorizationServers) == 0 {
		return
	}
	for _, detail := range details {
		detail["locations"] = []string{md.CredentialIssuer}
	}
}

// newPKCE returns an RFC 7636 S256 verifier and challenge and an RFC 6749
// state.
func newPKCE() (verifier, challenge, state string, err error) {
	if verifier, err = randomBase64URL(32); err != nil {
		return "", "", "", err
	}
	if state, err = randomBase64URL(16); err != nil {
		return "", "", "", err
	}
	digest := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(digest[:]), state, nil
}

// pushedAuthorizationRequired reports whether the authorization request is
// pushed: whenever the server has a PAR endpoint. A server without one is
// refused when the profile requires PAR (Options.RequirePAR, HAIP Section 4)
// or the server itself does (RFC 9126 Section 5
// require_pushed_authorization_requests); otherwise, as OpenID4VCI 1.0 and
// Draft 13 allow, the parameters travel inline.
func pushedAuthorizationRequired(as *receiverTypes.AuthorizationServerMetadata, profileRequiresPAR bool) (bool, error) {
	if as.PushedAuthorizationRequestEndpoint != nil {
		return true, nil
	}
	if profileRequiresPAR {
		return false, invalidMetadata("%w requires a pushed authorization request endpoint on the authorization server", profile.Refused("RequirePAR"))
	}
	if as.RequirePushedAuthorizationRequests != nil && *as.RequirePushedAuthorizationRequests {
		return false, invalidMetadata("the authorization server requires pushed authorization requests (RFC 9126 Section 5) and advertises no pushed_authorization_request_endpoint")
	}
	return false, nil
}

// acceptPushedAuthorization checks the RFC 9126 Section 2.2 response of a
// pushed authorization request (request_uri and a positive expires_in, both
// REQUIRED), records the request_uri's expiry on authorization and returns
// the request_uri. A pushed request that failed is never replaced by the
// parameters inline.
func acceptPushedAuthorization(authorization *IssuanceAuthorization, pushed *receiverTypes.PushedAuthorizationResponse, err error) (string, error) {
	if err != nil {
		return "", fmt.Errorf("failed to push authorization request: %w", err)
	}
	if pushed == nil || strings.TrimSpace(pushed.RequestURI) == "" {
		return "", fmt.Errorf("%w: the response carries no request_uri", receiverTypes.ErrPARResponseInvalid)
	}
	if pushed.ExpiresIn <= 0 {
		return "", fmt.Errorf("%w: expires_in must be a positive integer, got %d", receiverTypes.ErrPARResponseInvalid, pushed.ExpiresIn)
	}
	authorization.RequestURIExpiresAt = time.Now().Add(time.Duration(pushed.ExpiresIn) * time.Second)
	return pushed.RequestURI, nil
}

// requireSecureAuthorizationEndpoint refuses an authorization endpoint the
// holder's browser would open without TLS: OpenID4VCI 1.0 Section 11 and
// FAPI 2.0 Section 5.2.1 (HAIP Section 4) require TLS for every endpoint, and
// the wallet never fetches this one itself, so the receiver's scheme check
// does not reach it. Plain http is allowed only when the receiver allows it
// (receiverTypes.HTTPSchemePolicy, experimental and never under
// ForbidExperimental).
func requireSecureAuthorizationEndpoint(transport any, endpoint *common.URIField) error {
	endpointURL := url.URL(*endpoint)
	if strings.EqualFold(endpointURL.Scheme, "https") {
		return nil
	}
	if policy, ok := transport.(receiverTypes.HTTPSchemePolicy); ok && policy.HTTPAllowed() && strings.EqualFold(endpointURL.Scheme, "http") {
		return nil
	}
	return invalidMetadata("the authorization endpoint %q does not use https", endpointURL.String())
}

// authorizationRequestURL builds the authorization request URL. With a PAR
// request_uri only client_id and request_uri are sent (RFC 9126 Section 4);
// otherwise the parameters travel inline.
func authorizationRequestURL(endpoint *common.URIField, clientID string, request receiverTypes.PushedAuthorizationRequest, requestURI string) string {
	authorizationURL := url.URL(*endpoint)
	query := authorizationURL.Query()
	query.Set("client_id", clientID)
	if requestURI != "" {
		query.Set("request_uri", requestURI)
		authorizationURL.RawQuery = query.Encode()
		return authorizationURL.String()
	}
	query.Set("response_type", request.ResponseType)
	query.Set("redirect_uri", request.RedirectURI)
	query.Set("state", request.State)
	query.Set("code_challenge", request.CodeChallenge)
	query.Set("code_challenge_method", request.CodeChallengeMethod)
	if request.Scope != "" {
		query.Set("scope", request.Scope)
	}
	if len(request.AuthorizationDetails) > 0 {
		if encoded, err := json.Marshal(request.AuthorizationDetails); err == nil {
			query.Set("authorization_details", string(encoded))
		}
	}
	if request.IssuerState != "" {
		query.Set("issuer_state", request.IssuerState)
	}
	authorizationURL.RawQuery = query.Encode()
	return authorizationURL.String()
}

// authorizationResponseIssuerPolicy is the RFC 9207 expectation: expected is
// the authorization server's issuer identifier, and required makes iss
// mandatory. option names the profile option that made it mandatory, empty
// when the server's own metadata did.
type authorizationResponseIssuerPolicy struct {
	expected string
	required bool
	option   string
}

// validateAuthorizationRedirect applies RFC 6749 Section 4.1.2 and RFC 9207
// Section 2.4 to the redirect and returns the code. The target, state and iss
// are checked before the redirect is read as an error, so a forged error
// redirect cannot abort the issuance (RFC 6749 Section 10.12). A relative
// location resolves against authorizationURL.
func validateAuthorizationRedirect(location, authorizationURL, expectedState, registeredRedirectURI string, issuer authorizationResponseIssuerPolicy) (string, error) {
	redirectURL, err := url.Parse(location)
	if err != nil {
		return "", fmt.Errorf("failed to parse authorization redirect: %w: %w", ErrAuthorizationRedirectInvalid, err)
	}
	if !redirectURL.IsAbs() {
		base, err := url.Parse(authorizationURL)
		if err != nil {
			return "", fmt.Errorf("failed to parse authorization endpoint URL: %w: %w", ErrAuthorizationRedirectInvalid, err)
		}
		redirectURL = base.ResolveReference(redirectURL)
	}
	registeredRedirect, err := url.Parse(registeredRedirectURI)
	if err != nil {
		return "", fmt.Errorf("failed to parse registered redirect URI: %w: %w", ErrAuthorizationRedirectURIMismatch, err)
	}
	if !sameOriginAndPath(registeredRedirect, redirectURL) {
		return "", ErrAuthorizationRedirectURIMismatch
	}
	query := redirectURL.Query()
	if query.Get("state") != expectedState {
		return "", ErrAuthorizationStateMismatch
	}
	if iss, present := query["iss"]; present {
		if len(iss) != 1 || iss[0] != issuer.expected {
			return "", ErrAuthorizationIssMismatch
		}
	} else if issuer.required {
		if issuer.option != "" {
			return "", fmt.Errorf("%w requires the iss authorization response parameter: %w", profile.Refused(issuer.option), ErrAuthorizationIssMissing)
		}
		return "", ErrAuthorizationIssMissing
	}
	if errorCode := query.Get("error"); errorCode != "" {
		return "", &AuthorizationResponseError{
			Code:        errorCode,
			Description: query.Get("error_description"),
			State:       query.Get("state"),
		}
	}
	code := query.Get("code")
	if code == "" {
		return "", ErrAuthorizationCodeMissing
	}
	return code, nil
}

func sameOriginAndPath(registered, actual *url.URL) bool {
	return strings.EqualFold(registered.Scheme, actual.Scheme) &&
		strings.EqualFold(registered.Host, actual.Host) &&
		registered.Path == actual.Path
}

// authorizationDetailsMode records whether the request used
// authorization_details, which makes them REQUIRED in the Token Response
// (OpenID4VCI 1.0 Section 6.2: "REQUIRED when the authorization_details
// parameter ... is used ... OPTIONAL when scope parameter was used"; Draft 13
// Section 6.2 likewise), and what the entry must then carry.
type authorizationDetailsMode int

const (
	// authorizationDetailsOptional: the request used scope, or no parameter
	// (Pre-Authorized Code Flow).
	authorizationDetailsOptional authorizationDetailsMode = iota
	// authorizationDetailsRequired (OpenID4VCI 1.0 Section 6.2): the entry
	// for the configuration and its credential_identifiers, "REQUIRED. A
	// non-empty array".
	authorizationDetailsRequired
	// authorizationDetailsEntryRequired (Draft 13 Section 6.2): the entry for
	// the configuration; its credential_identifiers are OPTIONAL, and without
	// them the Credential Request names the format (Draft 13 Section 7.2).
	authorizationDetailsEntryRequired
)

// credentialIdentifiersFor returns the credential_identifiers of the Token
// Response entry for configurationID (Section 6.2), in the order the server
// listed them: each names a Credential Dataset the access token can be used
// for. An entry without identifiers, or no entry, yields none, so the request
// names the configuration instead, unless mode requires the entry (both
// required modes) or its identifiers (authorizationDetailsRequired), which is
// then ErrAuthorizationDetailsMissing.
func credentialIdentifiersFor(token *receiverTypes.CredentialIssuanceAccessToken, configurationID string, mode authorizationDetailsMode) ([]string, error) {
	entryRequired := mode != authorizationDetailsOptional
	if token == nil {
		if entryRequired {
			return nil, fmt.Errorf("token response is missing an access token with authorization_details for %q: %w", configurationID, ErrAuthorizationDetailsMissing)
		}
		return nil, nil
	}
	entries := 0
	for _, detail := range token.AuthorizationDetails {
		if detail.Type != receiverTypes.AuthorizationDetailTypeOpenIDCredential {
			continue
		}
		entries++
		if detail.CredentialConfigurationID != configurationID {
			continue
		}
		identifiers := nonEmptyCredentialIdentifiers(detail.CredentialIdentifiers)
		if len(identifiers) == 0 && mode == authorizationDetailsRequired {
			return nil, fmt.Errorf("authorization_details entry for credential_configuration_id %q carries no credential_identifiers: %w", configurationID, ErrAuthorizationDetailsMissing)
		}
		if len(identifiers) == 0 {
			return nil, nil
		}
		return identifiers, nil
	}
	switch {
	case entries == 0 && entryRequired:
		return nil, fmt.Errorf("token response for credential_configuration_id %q carries no authorization_details: %w", configurationID, ErrAuthorizationDetailsMissing)
	case entries == 0:
		return nil, nil
	case entryRequired:
		return nil, fmt.Errorf("token response authorization_details carries no entry for credential_configuration_id %q: %w", configurationID, ErrAuthorizationDetailsMissing)
	}
	return nil, fmt.Errorf("access token authorization_details contains no entry for credential_configuration_id %q: %w", configurationID, receiverTypes.ErrInvalidTokenResponse)
}

// selectCredentialIdentifier returns the credential_identifier the Credential
// Request names: requested, which must be one of the grant's identifiers, or
// the first of them; "" when the grant has none and the request names the
// configuration (OpenID4VCI 1.0 Section 8.2, Draft 13 Section 7.2).
func selectCredentialIdentifier(grant *IssuanceGrant, requested string) (string, error) {
	requested = strings.TrimSpace(requested)
	switch {
	case requested != "" && !slices.Contains(grant.CredentialIdentifiers, requested):
		return "", invalidArgument("credential_identifier %q is not one of the grant's credential_identifiers %v", requested, grant.CredentialIdentifiers)
	case requested != "":
		return requested, nil
	case len(grant.CredentialIdentifiers) > 0:
		return grant.CredentialIdentifiers[0], nil
	}
	return "", nil
}

// nonEmptyCredentialIdentifiers drops blank identifiers.
func nonEmptyCredentialIdentifiers(identifiers []string) []string {
	usable := identifiers[:0:0]
	for _, identifier := range identifiers {
		if strings.TrimSpace(identifier) != "" {
			usable = append(usable, identifier)
		}
	}
	return usable
}
