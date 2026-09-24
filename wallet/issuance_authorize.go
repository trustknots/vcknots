package wallet

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/trustknots/vcknots/wallet/common"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// BeginIssuance starts an OpenID4VCI 1.0 Authorization Code Flow: it resolves
// the issuer and authorization server metadata, checks the configuration
// against the wallet profile and Config.Issuance.CredentialEncryption, pushes
// the authorization request when the server supports RFC 9126 PAR (HAIP
// requires it), and returns the state holding the URL to open in the holder's
// browser. The library does not open it. Config.ClientAuth.ClientID and
// Config.Issuance.RedirectURI identify the wallet.
func (w *Wallet) BeginIssuance(ctx context.Context, req IssuanceRequest) (*IssuanceAuthorization, error) {
	authorization, err := w.beginIssuance(ctx, req)
	return authorization, classify(err)
}

func (w *Wallet) beginIssuance(ctx context.Context, req IssuanceRequest) (*IssuanceAuthorization, error) {
	if err := w.requireFinalAuthorizationStage(ctx); err != nil {
		return nil, err
	}
	clientID, redirectURI, err := w.authorizationCodeClient()
	if err != nil {
		return nil, err
	}
	var issuer, configurationID, issuerState, hint string
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
	if as.TokenEndpoint == nil {
		return nil, invalidMetadata("token endpoint is missing on authorization server")
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
	// HAIP Section 4 requires PAR; OpenID4VCI 1.0 does not, so a Final
	// issuer without a PAR endpoint gets the parameters inline.
	usePAR := as.PushedAuthorizationRequestEndpoint != nil
	if !usePAR && w.profile.IsHAIP() {
		return nil, invalidMetadata("HAIP requires a pushed authorization request endpoint on the authorization server")
	}
	scope, details, err := authorizationRequestParameters(req.AuthorizationRequestType, configurationID, config, w.profile.IsHAIP())
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
		Version:                       IssuanceVersionFinal,
		State:                         state,
		CodeVerifier:                  verifier,
		CredentialIssuer:              md.CredentialIssuer,
		CredentialConfigurationID:     configurationID,
		AuthorizationServer:           discovery.authorizationServer,
		ClientID:                      clientID,
		RedirectURI:                   redirectURI,
		AuthorizationDetailsRequested: len(details) > 0,
	}
	requestURI := ""
	if usePAR {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		// RFC 9126 Section 2: the PAR endpoint authenticates the client like
		// the token endpoint (HAIP Section 4.4.1).
		auth, err := w.clientAuthentication(ctx, transport, discovery, false)
		if err != nil {
			return nil, err
		}
		pushed, err := transport.PushAuthorizationRequest(ctx, *as.PushedAuthorizationRequestEndpoint, request, auth)
		if err != nil {
			return nil, fmt.Errorf("failed to push authorization request: %w", err)
		}
		requestURI = pushed.RequestURI
		if pushed.ExpiresIn > 0 {
			authorization.RequestURIExpiresAt = time.Now().Add(time.Duration(pushed.ExpiresIn) * time.Second)
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
// *AuthorizationResponseError.
func (w *Wallet) AuthorizeIssuance(ctx context.Context, authorization *IssuanceAuthorization, redirectURL string) (*IssuanceGrant, error) {
	grant, err := w.authorizeIssuance(ctx, authorization, redirectURL)
	return grant, classify(err)
}

func (w *Wallet) authorizeIssuance(ctx context.Context, a *IssuanceAuthorization, redirectURL string) (*IssuanceGrant, error) {
	if err := w.checkAuthorizationState(a, IssuanceVersionFinal); err != nil {
		return nil, err
	}
	if err := w.requireFinalAuthorizationStage(ctx); err != nil {
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
	code, err := validateAuthorizationRedirect(redirectURL, a.AuthorizationURL, a.State, a.RedirectURI, authorizationResponseIssuerPolicy{
		expected: discovery.authorizationServer,
		// FAPI 2.0 Section 5.3.2.2, which HAIP builds on, requires the check.
		required: w.profile.IsHAIP() || (advertised != nil && *advertised),
	})
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	auth, err := w.clientAuthentication(ctx, transport, discovery, false)
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
	return w.newFinalGrant(ctx, transport, discovery, a.CredentialConfigurationID, config, token, mode)
}

// checkAuthorizationState checks that a is a complete state of version and
// was created with the wallet's client_id and redirect_uri.
func (w *Wallet) checkAuthorizationState(a *IssuanceAuthorization, version IssuanceVersion) error {
	if a == nil {
		return invalidArgument("authorization state is required")
	}
	if a.Version != version {
		return fmt.Errorf("authorization state has version %q: %w", a.Version, ErrIssuanceVersionMismatch)
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
// stage: a live context, an acceptance policy, and under HAIP a DPoP key (HAIP
// Section 4).
func (w *Wallet) requireFinalIssuance(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if w.credentialAcceptance == nil {
		return fmt.Errorf("issuer verification is not configured: %w", ErrCredentialAcceptancePolicyRequired)
	}
	if w.profile.IsHAIP() && w.dpop.Key == nil {
		return fmt.Errorf("HAIP requires Config.DPoP.Key: %w", ErrDPoPKeyRequired)
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
	if w.profile.IsHAIP() && w.attestationSettings().Client == nil && !clientAuthenticationConfigured(w.clientAuth) {
		return invalidArgument("HAIP requires an OAuth2 client authentication mechanism")
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
	validator, _ := transport.(oid4vciProfileValidator)
	if w.profile.IsHAIP() && validator == nil {
		return config, invalidArgument("HAIP requires a receiver plugin that validates issuer metadata against the profile")
	}
	if validator != nil {
		if err := validator.ValidateCredentialConfigurationForProfile(config); err != nil {
			return config, fmt.Errorf("credential configuration does not satisfy the wallet profile: %w", withCode(receiverTypes.ErrInvalidMetadata, err))
		}
	}
	return config, requireJWTProofType(id, config)
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
	if _, ok := resolveClientAuthMethod(w.clientAuth, as); !ok {
		return errNoUsableClientAuthMethod
	}
	return nil
}

// clientAuthentication returns how the client authenticates at the PAR and
// token endpoints: a Client Attestation when Config.Attestation.Client is set,
// else private_key_jwt when configured. Attestation and private_key_jwt are
// alternatives. preAuthorized also requires anonymous access to be allowed
// when neither is used. DPoP is left to the caller.
func (w *Wallet) clientAuthentication(ctx context.Context, transport receiverTypes.AuthorizationTransport, discovery *issuanceDiscovery, preAuthorized bool) (receiverTypes.ClientAuthentication, error) {
	var auth receiverTypes.ClientAuthentication
	attestationHeaders, err := w.clientAttestationFactory(ctx, transport, discovery.asMetadata, discovery.authorizationServer)
	if err != nil {
		return auth, err
	}
	if attestationHeaders != nil {
		auth.ClientAttestation = attestationHeaders
		return auth, nil
	}
	method, ok := resolveClientAuthMethod(w.clientAuth, discovery.asMetadata)
	if preAuthorized && !ok {
		return auth, errNoUsableClientAuthMethod
	}
	if method == receiverTypes.PrivateKeyJwt {
		auth.ClientAssertion = w.privateKeyJWTFactory(ctx, discovery.asMetadata)
	}
	return auth, nil
}

// authorizationRequestParameters resolves the scope or authorization_details
// that request the configuration (OpenID4VCI 1.0 Sections 5.1.1, 5.1.2). The
// default is scope when advertised, since without one "the only way to request
// the Credential is using authorization_details" (Section 12.2.4). HAIP allows
// scope only (HAIP Sections 4.2, 4.3).
func authorizationRequestParameters(requested AuthorizationRequestType, configurationID string, config receiverTypes.CredentialConfiguration, haip bool) (string, []map[string]any, error) {
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
		if haip {
			return "", nil, invalidMetadata("HAIP requires the credential configuration %q to advertise a scope", configurationID)
		}
		return "", details, nil
	case AuthorizationRequestScope:
		if scope == "" {
			if haip {
				return "", nil, invalidMetadata("HAIP requires the credential configuration %q to advertise a scope", configurationID)
			}
			return "", nil, invalidMetadata("authorization request type %q requires the credential configuration %q to advertise a scope", AuthorizationRequestScope, configurationID)
		}
		return config.Scope, nil, nil
	case AuthorizationRequestDetails:
		if haip {
			return "", nil, invalidArgument("HAIP requires the scope authorization request type")
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
// mandatory.
type authorizationResponseIssuerPolicy struct {
	expected string
	required bool
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
// authorization_details, which OpenID4VCI 1.0 Section 6.2 makes "REQUIRED
// when the authorization_details parameter is used ... OPTIONAL when scope
// parameter was used" in the Token Response.
type authorizationDetailsMode int

const (
	authorizationDetailsOptional authorizationDetailsMode = iota
	authorizationDetailsRequired
)

// credentialIdentifiersFor selects the credential_identifiers of the Token
// Response entry for configurationID (Section 6.2). The selected identifier is
// the first; an entry without identifiers, or no entry, names the
// configuration instead in optional mode. In required mode those cases, an
// entry for another configuration only, and more than one identifier are
// ErrAuthorizationDetailsMissing.
func credentialIdentifiersFor(token *receiverTypes.CredentialIssuanceAccessToken, configurationID string, mode authorizationDetailsMode) ([]string, error) {
	required := mode == authorizationDetailsRequired
	if token == nil {
		if required {
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
		switch {
		case len(identifiers) == 0 && required:
			return nil, fmt.Errorf("authorization_details entry for credential_configuration_id %q carries no credential_identifiers: %w", configurationID, ErrAuthorizationDetailsMissing)
		case len(identifiers) == 0:
			return nil, nil
		case len(identifiers) > 1 && required:
			return nil, fmt.Errorf("authorization_details entry for credential_configuration_id %q carries %d credential_identifiers, but this wallet requests exactly one credential: %w", configurationID, len(identifiers), ErrAuthorizationDetailsMissing)
		}
		return identifiers[:1], nil
	}
	switch {
	case entries == 0 && required:
		return nil, fmt.Errorf("token response for credential_configuration_id %q carries no authorization_details: %w", configurationID, ErrAuthorizationDetailsMissing)
	case entries == 0:
		return nil, nil
	case required:
		return nil, fmt.Errorf("token response authorization_details carries no entry for credential_configuration_id %q: %w", configurationID, ErrAuthorizationDetailsMissing)
	}
	return nil, fmt.Errorf("access token authorization_details contains no entry for credential_configuration_id %q: %w", configurationID, receiverTypes.ErrInvalidTokenResponse)
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
