package wallet

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/attestation"
	"github.com/trustknots/vcknots/wallet/common/observe"
	"github.com/trustknots/vcknots/wallet/internal/httpfetch"
	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
	"github.com/trustknots/vcknots/wallet/keystore"
	"github.com/trustknots/vcknots/wallet/profile"
	"github.com/trustknots/vcknots/wallet/receiver"
	"github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// fixtureRedirectURI is the redirect_uri the fixture wallet registers.
const fixtureRedirectURI = "openid-credential-offer://callback"

// mustDecodeObservedCredentialRequest decodes a Credential Request body from
// the fixture's handler goroutine, recording a decoding failure on obs.
func mustDecodeObservedCredentialRequest(obs *serverObservations, r *http.Request, key jose.JSONWebKey) map[string]any {
	body, _ := decodeObservedCredentialRequest(obs, r, key)
	return body
}

// finalIssuanceFixture is an OpenID4VCI 1.0 Credential Issuer and
// Authorization Server on one httptest server, and a wallet configured for it.
// Options change the fixture before the server and the wallet are built.
type finalIssuanceFixture struct {
	t      *testing.T
	server *httptest.Server
	wallet *Wallet
	// obs records what the handlers observed, reported when the test ends.
	obs *serverObservations

	// holderKey, additionalKey and clientKey are private JWKs; holderEntry,
	// additionalEntry and dpopEntry are the key entries the wallet signs
	// with. clientKey is the wallet's DPoP key and the key a client
	// attestation binds.
	holderKey       jose.JSONWebKey
	additionalKey   jose.JSONWebKey
	clientKey       jose.JSONWebKey
	attesterKey     jose.JSONWebKey
	encryptionKey   jose.JSONWebKey
	holderEntry     IKeyEntry
	additionalEntry IKeyEntry
	dpopEntry       IKeyEntry
	// issuerKey signs every credential; the wallet's acceptance policy
	// resolves it.
	issuerKey *ecdsa.PrivateKey
	// requestEncryptionKey backs credential_request_encryption.
	requestEncryptionKey jose.JSONWebKey

	issuedCredential string

	credentialIssuerOverride string
	authorizationServers     []string
	asIssuerOverride         string
	includeNonceEndpoint     bool
	includeDeferredEndpoint  bool
	includeNotification      bool
	responseEncryption       bool
	encryptionRequired       bool
	// responseAlgValues and responseEncValues, when set, are the
	// credential_response_encryption alg and enc values published.
	responseAlgValues     []string
	responseEncValues     []string
	requestEncryption     bool
	omitPAREndpoint       bool
	issParameterSupported bool
	// walletProfile selects the wallet and plugin profile; HAIP also serves
	// TLS (HAIP Section 4).
	walletProfile           profile.Profile
	clientAuthKey           IKeyEntry
	omitScope               bool
	keyAttestationsRequired bool
	// proofTypesSupported, when set, is published verbatim.
	proofTypesSupported map[string]any
	// credentialFormat, when set, replaces the configuration's dc+sd-jwt.
	credentialFormat         string
	bindingMethods           []string
	batchSize                int
	parExpiresIn             int
	authMethodsSupported     []receiverTypes.TokenEndpointAuthMethod
	authSigningAlgsSupported []jose.SignatureAlgorithm
	authorizeLocation        func(f *finalIssuanceFixture, state string) string
	// hsmKeys makes every wallet key an hsmKeyEntry, which holds no private
	// JWK.
	hsmKeys bool
	// noDPoPKey builds the wallet without a DPoP key.
	noDPoPKey bool
	// Wallet configuration.
	clientAttestation  attestation.ClientProvider
	keyAttestation     attestation.KeyProvider
	attestationTrust   attestation.TrustPolicy
	encryptionPolicy   CredentialEncryptionPolicy
	noAcceptancePolicy bool
	// wrapReceiverPlugin decorates the bundled plugin before registration.
	wrapReceiverPlugin func(receiverTypes.Receiver) receiverTypes.Receiver
	tokenResponse      map[string]any
	tokenHandler       http.HandlerFunc
	nonceHandler       http.HandlerFunc
	credentialHandler  http.HandlerFunc
	deferredHandler    http.HandlerFunc
	// notificationHandler replaces the default 204 after the request was
	// recorded.
	notificationHandler http.HandlerFunc

	issuerMetadataCalls int
	asMetadataCalls     int
	parCalls            int
	authorizeCalls      int
	tokenCalls          int
	nonceCalls          int
	credentialCalls     int
	deferredCalls       int
	notificationEvents  []string
	notificationBodies  []map[string]any
	notificationHeaders []http.Header
	pushedState         string
	lastCredentialBody  map[string]any
	lastDeferredBody    map[string]any
	credentialHeaders   http.Header
	authorizeQuery      url.Values
	parForm             url.Values
	parHeaders          http.Header
	tokenHeaders        http.Header
	// tokenHeaderList records every token request's headers.
	tokenHeaderList []http.Header
	tokenForms      []url.Values
}

func newFinalIssuanceFixture(t *testing.T, opts ...func(*finalIssuanceFixture)) *finalIssuanceFixture {
	t.Helper()
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	f := &finalIssuanceFixture{
		t:                    t,
		obs:                  newServerObservations(t),
		holderKey:            newPrivateJWKForFinalVCITest(t, "holder-key-1"),
		additionalKey:        newPrivateJWKForFinalVCITest(t, "holder-key-2"),
		clientKey:            newPrivateJWKForFinalVCITest(t, "client-key-1"),
		attesterKey:          newPrivateJWKForFinalVCITest(t, "attester-key-1"),
		issuerKey:            issuerKey,
		includeNonceEndpoint: true,
		parExpiresIn:         60,
	}
	f.encryptionKey = newPrivateJWKForFinalVCITest(t, "credential-response-enc-key-1")
	f.encryptionKey.Algorithm = "ECDH-ES"
	f.encryptionKey.Use = "enc"
	f.requestEncryptionKey = newPrivateJWKForFinalVCITest(t, "credential-request-enc-key-1")
	f.requestEncryptionKey.Algorithm = "ECDH-ES"
	f.requestEncryptionKey.Use = "enc"

	for _, opt := range opts {
		opt(f)
	}
	f.holderEntry = f.keyEntry(f.holderKey)
	f.additionalEntry = f.keyEntry(f.additionalKey)
	f.dpopEntry = f.keyEntry(f.clientKey)
	f.issuedCredential = f.issueCredential(f.holderKey, map[string]string{"given_name": "Taro"})
	if f.walletProfile.IsHAIP() {
		f.server = httptest.NewTLSServer(http.HandlerFunc(f.serveHTTP))
	} else {
		f.server = httptest.NewServer(http.HandlerFunc(f.serveHTTP))
	}
	t.Cleanup(f.server.Close)
	f.wallet = f.newWallet(t)
	return f
}

// newWallet builds a wallet for the fixture server with the fixture's
// configuration. Each call registers a fresh receiver plugin.
func (f *finalIssuanceFixture) newWallet(t *testing.T) *Wallet {
	t.Helper()
	plugin := receiverTypes.Receiver(&oid4vci.Oid4vciReceiver{
		HTTPClient: f.server.Client(),
		AllowHTTP:  !f.walletProfile.IsHAIP(),
		Profile:    f.walletProfile,
	})
	if f.wrapReceiverPlugin != nil {
		plugin = f.wrapReceiverPlugin(plugin)
	}
	receiving, err := receiver.NewReceivingDispatcher(receiver.WithPlugin(receiverTypes.Oid4vci, plugin))
	require.NoError(t, err)
	config := Config{
		Profile:    f.walletProfile,
		CredStore:  newProfileCredStore(t),
		Receiver:   receiving,
		ClientAuth: ClientAuthConfig{ClientID: "client-1"},
		Issuance:   IssuanceConfig{RedirectURI: fixtureRedirectURI, CredentialEncryption: f.encryptionPolicy},
		Attestation: AttestationConfig{
			Client: f.clientAttestation,
			Key:    f.keyAttestation,
			Trust:  f.attestationTrust,
		},
	}
	if !f.noDPoPKey {
		config.DPoP = DPoPConfig{Key: f.dpopEntry}
	}
	if !f.noAcceptancePolicy {
		config.CredentialAcceptance = acceptIssuerKeyPolicy(f.issuerKey)
	}
	if f.clientAuthKey != nil {
		config.ClientAuth = ClientAuthConfig{Method: receiverTypes.PrivateKeyJwt, ClientID: "client-1", Key: f.clientAuthKey}
	}
	w, err := NewWalletWithConfig(config)
	require.NoError(t, err)
	return w
}

// newHAIPIssuanceFixture is newFinalIssuanceFixture under HAIP: TLS,
// private_key_jwt (HAIP Section 4.4.1) and the RFC 9207 iss parameter.
func newHAIPIssuanceFixture(t *testing.T, opts ...func(*finalIssuanceFixture)) *finalIssuanceFixture {
	t.Helper()
	clientAuthKey, _ := newClientAuthKeyEntry(t, "client-auth-key-1")
	haip := append([]func(*finalIssuanceFixture){func(f *finalIssuanceFixture) {
		f.walletProfile = profile.HAIP
		f.clientAuthKey = clientAuthKey
		f.issParameterSupported = true
		f.authMethodsSupported = []receiverTypes.TokenEndpointAuthMethod{receiverTypes.PrivateKeyJwt}
		f.authSigningAlgsSupported = []jose.SignatureAlgorithm{jose.ES256}
	}}, opts...)
	return newFinalIssuanceFixture(t, haip...)
}

// keyEntry returns the wallet's key entry for jwk: an in-memory one, or an
// hsmKeyEntry under hsmKeys.
func (f *finalIssuanceFixture) keyEntry(jwk jose.JSONWebKey) IKeyEntry {
	f.t.Helper()
	if f.hsmKeys {
		return newHSMKeyEntry(jwk)
	}
	entry, err := keystore.NewKeyEntryFromJWK(jwk)
	require.NoError(f.t, err)
	return entry
}

// issueCredential signs an SD-JWT VC with the fixture's issuer key.
func (f *finalIssuanceFixture) issueCredential(holderKey jose.JSONWebKey, claims map[string]string) string {
	return buildTestSDJWTVCWithIssuerKey(f.t, f.issuerKey, holderKey, claims)
}

func (f *finalIssuanceFixture) credentialIssuer(base string) string {
	if f.credentialIssuerOverride != "" {
		return f.credentialIssuerOverride
	}
	return base
}

func (f *finalIssuanceFixture) resolveAuthorizationServers(base string) []string {
	if f.authorizationServers != nil {
		return f.authorizationServers
	}
	return []string{base}
}

func (f *finalIssuanceFixture) authorizationServerIssuer(base string) string {
	if f.asIssuerOverride != "" {
		return f.asIssuerOverride
	}
	return base
}

func (f *finalIssuanceFixture) tokenResponseValue() map[string]any {
	if f.tokenResponse != nil {
		return f.tokenResponse
	}
	return map[string]any{"access_token": "access-1", "token_type": "DPoP", "expires_in": 3600}
}

func (f *finalIssuanceFixture) authorizeRedirect(base string) string {
	if f.authorizeLocation != nil {
		return f.authorizeLocation(f, f.pushedState)
	}
	location := fixtureRedirectURI + "?code=code-1&state=" + url.QueryEscape(f.pushedState)
	if f.issParameterSupported {
		location += "&iss=" + url.QueryEscape(f.authorizationServerIssuer(base))
	}
	return location
}

// writeDefaultCredentialResponse encrypts the response when the request asked
// for it (Section 8.2).
func (f *finalIssuanceFixture) writeDefaultCredentialResponse(w http.ResponseWriter, payload any) {
	if f.responseEncryption && f.responseEncryptionRequested() {
		writeObservedFinalCredentialResponse(f.obs, w, f.responseKeyFromRequest(), payload)
		return
	}
	mockserver.JSONResponse(w, http.StatusOK, payload)
}

// responseEncryptionRequested reports whether the last (Deferred) Credential
// Request carried credential_response_encryption.
func (f *finalIssuanceFixture) responseEncryptionRequested() bool {
	return f.lastCredentialBody["credential_response_encryption"] != nil ||
		(f.lastDeferredBody != nil && f.lastDeferredBody["credential_response_encryption"] != nil)
}

// responseKeyFromRequest is the credential_response_encryption.jwk of the
// last (Deferred) Credential Request; the wallet's key is ephemeral.
func (f *finalIssuanceFixture) responseKeyFromRequest() jose.JSONWebKey {
	body := f.lastCredentialBody
	if f.lastDeferredBody != nil && f.lastDeferredBody["credential_response_encryption"] != nil {
		body = f.lastDeferredBody
	}
	encryption, _ := body["credential_response_encryption"].(map[string]any)
	raw, err := json.Marshal(encryption["jwk"])
	if err != nil {
		f.obs.Errorf("credential_response_encryption.jwk: %v", err)
		return jose.JSONWebKey{}
	}
	var key jose.JSONWebKey
	if err := key.UnmarshalJSON(raw); err != nil {
		f.obs.Errorf("credential_response_encryption.jwk: %v", err)
	}
	return key
}

func (f *finalIssuanceFixture) serveHTTP(w http.ResponseWriter, r *http.Request) {
	base := f.server.URL
	switch r.URL.Path {
	case "/.well-known/openid-credential-issuer":
		f.issuerMetadataCalls++
		credentialConfiguration := map[string]any{"format": "dc+sd-jwt"}
		if f.credentialFormat != "" {
			credentialConfiguration["format"] = f.credentialFormat
		}
		if !f.omitScope {
			credentialConfiguration["scope"] = "pid-scope"
		}
		if f.bindingMethods != nil {
			credentialConfiguration["cryptographic_binding_methods_supported"] = f.bindingMethods
		}
		if f.proofTypesSupported != nil {
			credentialConfiguration["proof_types_supported"] = f.proofTypesSupported
		}
		if f.keyAttestationsRequired {
			credentialConfiguration["proof_types_supported"] = map[string]any{
				"jwt": map[string]any{
					"proof_signing_alg_values_supported": []string{"ES256"},
					"key_attestations_required":          map[string]any{"key_storage": []string{"iso_18045_high"}},
				},
			}
		}
		metadata := map[string]any{
			"credential_issuer":     f.credentialIssuer(base),
			"credential_endpoint":   base + "/credential",
			"authorization_servers": f.resolveAuthorizationServers(base),
			"credential_configurations_supported": map[string]any{
				"pid": credentialConfiguration,
			},
		}
		if f.includeNonceEndpoint {
			metadata["nonce_endpoint"] = base + "/nonce"
		}
		if f.includeDeferredEndpoint {
			metadata["deferred_credential_endpoint"] = base + "/deferred"
		}
		if f.includeNotification {
			metadata["notification_endpoint"] = base + "/notification"
		}
		if f.batchSize > 0 {
			metadata["batch_credential_issuance"] = map[string]any{"batch_size": f.batchSize}
		}
		if f.responseEncryption {
			responseEncryption := map[string]any{
				"enc_values_supported": []string{"A128GCM"},
				"encryption_required":  f.encryptionRequired,
			}
			if f.responseAlgValues != nil {
				responseEncryption["alg_values_supported"] = f.responseAlgValues
			}
			if f.responseEncValues != nil {
				responseEncryption["enc_values_supported"] = f.responseEncValues
			}
			metadata["credential_response_encryption"] = responseEncryption
		}
		if f.requestEncryption {
			metadata["credential_request_encryption"] = map[string]any{
				"jwks":                 map[string]any{"keys": []any{f.requestEncryptionKey.Public()}},
				"enc_values_supported": []string{"A128GCM"},
				"encryption_required":  true,
			}
		}
		mockserver.JSONResponse(w, http.StatusOK, metadata)
	case "/.well-known/oauth-authorization-server":
		f.asMetadataCalls++
		metadata := map[string]any{
			"issuer":                 f.authorizationServerIssuer(base),
			"authorization_endpoint": base + "/authorize",
			"token_endpoint":         base + "/token",
			"pre-authorized_grant_anonymous_access_supported": true,
			"response_types_supported":                        []string{"code"},
		}
		if !f.omitPAREndpoint {
			metadata["pushed_authorization_request_endpoint"] = base + "/par"
		}
		if f.issParameterSupported {
			metadata["authorization_response_iss_parameter_supported"] = true
		}
		if f.authMethodsSupported != nil {
			metadata["token_endpoint_auth_methods_supported"] = f.authMethodsSupported
		}
		if f.authSigningAlgsSupported != nil {
			metadata["token_endpoint_auth_signing_alg_values_supported"] = f.authSigningAlgsSupported
		}
		mockserver.JSONResponse(w, http.StatusOK, metadata)
	case "/par":
		f.parCalls++
		_ = r.ParseForm()
		f.parForm = r.Form
		f.parHeaders = r.Header.Clone()
		f.pushedState = r.Form.Get("state")
		mockserver.JSONResponse(w, http.StatusOK, map[string]any{"request_uri": "urn:request:1", "expires_in": f.parExpiresIn})
	case "/authorize":
		f.authorizeCalls++
		f.authorizeQuery = r.URL.Query()
		if f.pushedState == "" {
			f.pushedState = r.URL.Query().Get("state")
		}
		w.Header().Set("Location", f.authorizeRedirect(base))
		w.WriteHeader(http.StatusFound)
	case "/token":
		f.tokenCalls++
		_ = r.ParseForm()
		f.tokenForms = append(f.tokenForms, r.Form)
		f.tokenHeaders = r.Header.Clone()
		f.tokenHeaderList = append(f.tokenHeaderList, f.tokenHeaders)
		if f.tokenHandler != nil {
			f.tokenHandler(w, r)
			return
		}
		mockserver.JSONResponse(w, http.StatusOK, f.tokenResponseValue())
	case "/nonce":
		f.nonceCalls++
		if f.nonceHandler != nil {
			f.nonceHandler(w, r)
			return
		}
		mockserver.JSONResponse(w, http.StatusOK, map[string]string{"c_nonce": "credential-nonce-1"})
	case "/credential":
		f.credentialCalls++
		f.credentialHeaders = r.Header.Clone()
		f.lastCredentialBody = mustDecodeObservedCredentialRequest(f.obs, r, f.requestEncryptionKey)
		if f.credentialHandler != nil {
			f.credentialHandler(w, r)
			return
		}
		payload := map[string]any{"credentials": []any{map[string]any{"credential": f.issuedCredential}}}
		if f.includeNotification {
			payload["notification_id"] = "notification-1"
		}
		f.writeDefaultCredentialResponse(w, payload)
	case "/deferred":
		f.deferredCalls++
		f.lastDeferredBody = mustDecodeObservedCredentialRequest(f.obs, r, f.requestEncryptionKey)
		if f.deferredHandler != nil {
			f.deferredHandler(w, r)
			return
		}
		payload := map[string]any{"credentials": []any{map[string]any{"credential": f.issuedCredential}}}
		if f.includeNotification {
			payload["notification_id"] = "notification-1"
		}
		f.writeDefaultCredentialResponse(w, payload)
	case "/notification":
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		event, _ := body["event"].(string)
		f.notificationEvents = append(f.notificationEvents, event)
		f.notificationBodies = append(f.notificationBodies, body)
		f.notificationHeaders = append(f.notificationHeaders, r.Header.Clone())
		if f.notificationHandler != nil {
			f.notificationHandler(w, r)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case "/offer":
		mockserver.JSONResponse(w, http.StatusOK, map[string]any{
			"credential_issuer":            base,
			"credential_configuration_ids": []string{"pid"},
			"grants": map[string]any{
				"authorization_code": map[string]any{"issuer_state": "issuer-state-1"},
			},
		})
	case "/bigoffer":
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"credential_issuer":"` + base + `","padding":"` + strings.Repeat("a", 64<<10) + `"}`))
	default:
		http.NotFound(w, r)
	}
}

// offer is an authorization_code Credential Offer for the "pid"
// configuration.
func (f *finalIssuanceFixture) offer() *CredentialOffer {
	issuerURL, err := url.Parse(f.server.URL)
	require.NoError(f.t, err)
	return &CredentialOffer{
		CredentialIssuer:           issuerURL,
		CredentialConfigurationIDs: []string{"pid"},
		Grants: map[string]*CredentialOfferGrant{
			"authorization_code": {IssuerState: "issuer-state-1"},
		},
	}
}

// issuanceRequest starts an Authorization Code Flow from offer.
func (f *finalIssuanceFixture) issuanceRequest() IssuanceRequest {
	return IssuanceRequest{CredentialOffer: f.offer()}
}

// walletInitiatedRequest starts the flow without an offer (OpenID4VCI 1.0
// Section 5).
func (f *finalIssuanceFixture) walletInitiatedRequest() IssuanceRequest {
	return IssuanceRequest{CredentialIssuer: f.server.URL, CredentialConfigurationID: "pid"}
}

// credentialRequest binds the credential to the holder key.
func (f *finalIssuanceFixture) credentialRequest() CredentialRequest {
	return CredentialRequest{HolderKeys: []IKeyEntry{f.holderEntry}}
}

// followAuthorization opens the authorization URL the way a browser that
// needs no user interaction would, and returns the redirect it got.
func (f *finalIssuanceFixture) followAuthorization(authorization *IssuanceAuthorization) (string, error) {
	return followAuthorizationRedirect(context.Background(), f.server.Client(), authorization.AuthorizationURL)
}

// authorize runs BeginIssuance, the authorization GET and AuthorizeIssuance.
func (f *finalIssuanceFixture) authorize(req IssuanceRequest) (*IssuanceGrant, error) {
	ctx := context.Background()
	authorization, err := f.wallet.BeginIssuance(ctx, req)
	if err != nil {
		return nil, err
	}
	location, err := f.followAuthorization(authorization)
	if err != nil {
		return nil, err
	}
	return f.wallet.AuthorizeIssuance(ctx, authorization, location)
}

// receive runs the whole Authorization Code Flow with the holder key.
func (f *finalIssuanceFixture) receive(req IssuanceRequest) (*IssuanceResult, error) {
	return f.receiveWith(req, f.credentialRequest())
}

// receiveWith runs the whole Authorization Code Flow with credentialRequest.
func (f *finalIssuanceFixture) receiveWith(req IssuanceRequest, credentialRequest CredentialRequest) (*IssuanceResult, error) {
	grant, err := f.authorize(req)
	if err != nil {
		return nil, err
	}
	return f.wallet.RequestCredential(context.Background(), grant, credentialRequest)
}

// followAuthorizationRedirect issues the authorization request as a GET and
// returns the Location it redirects to, without following it.
func followAuthorizationRedirect(ctx context.Context, client *http.Client, authorizationURL string) (string, error) {
	request, err := http.NewRequestWithContext(observe.WithEndpoint(ctx, observe.EndpointAuthorization), http.MethodGet, authorizationURL, nil)
	if err != nil {
		return "", err
	}
	response, err := httpfetch.NoRedirect(client).Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	location := response.Header.Get("Location")
	if location == "" {
		return "", fmt.Errorf("authorization endpoint did not redirect: %d", response.StatusCode)
	}
	return location, nil
}

func (f *finalIssuanceFixture) proofJWTs(t *testing.T) []string {
	t.Helper()
	proofs, ok := f.lastCredentialBody["proofs"].(map[string]any)
	require.True(t, ok, "request did not include proofs: %#v", f.lastCredentialBody)
	jwtRaw, ok := proofs["jwt"].([]any)
	require.True(t, ok)
	jwts := make([]string, 0, len(jwtRaw))
	for _, entry := range jwtRaw {
		value, ok := entry.(string)
		require.True(t, ok)
		jwts = append(jwts, value)
	}
	return jwts
}

func finalProofClaims(t *testing.T, proof string) map[string]any {
	t.Helper()
	claims, err := jwsClaims(proof)
	require.NoError(t, err)
	return claims
}

func finalProofHeader(t *testing.T, proof string) map[string]any {
	t.Helper()
	header, err := jwsHeader(proof)
	require.NoError(t, err)
	return header
}

// fixedKeyAttestationProvider returns a prebuilt key attestation whatever the
// request, modelling a misbehaving remote provider.
type fixedKeyAttestationProvider struct {
	attestation *attestation.KeyAttestation
}

func (p fixedKeyAttestationProvider) KeyAttestation(context.Context, attestation.KeyRequest) (*attestation.KeyAttestation, error) {
	return p.attestation, nil
}

// hsmKeyEntry is a key entry that holds no private JWK: PublicKey returns the
// public half only and Sign returns an ASN.1 DER signature, as a hardware
// module would.
type hsmKeyEntry struct {
	id      string
	private *ecdsa.PrivateKey
	public  jose.JSONWebKey
	signed  int
}

func newHSMKeyEntry(jwk jose.JSONWebKey) *hsmKeyEntry {
	private := jwk.Key.(*ecdsa.PrivateKey)
	return &hsmKeyEntry{
		id:      jwk.KeyID,
		private: private,
		public:  jose.JSONWebKey{Key: &private.PublicKey, KeyID: jwk.KeyID, Algorithm: jwk.Algorithm, Use: "sig"},
	}
}

func (k *hsmKeyEntry) ID() string                 { return k.id }
func (k *hsmKeyEntry) PublicKey() jose.JSONWebKey { return k.public }
func (k *hsmKeyEntry) Sign(data []byte) ([]byte, error) {
	k.signed++
	digest := sha256.Sum256(data)
	return ecdsa.SignASN1(rand.Reader, k.private, digest[:])
}

// requireJWKThumbprint fails unless want and got have the same RFC 7638
// thumbprint.
func requireJWKThumbprint(want jose.JSONWebKey, got jose.JSONWebKey) error {
	wantPublic, gotPublic := want.Public(), got.Public()
	wantThumbprint, err := wantPublic.Thumbprint(crypto.SHA256)
	if err != nil {
		return err
	}
	gotThumbprint, err := gotPublic.Thumbprint(crypto.SHA256)
	if err != nil {
		return err
	}
	if base64.RawURLEncoding.EncodeToString(wantThumbprint) != base64.RawURLEncoding.EncodeToString(gotThumbprint) {
		return fmt.Errorf("thumbprint mismatch")
	}
	return nil
}
