package wallet

import (
	"context"
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
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/acceptance"
	"github.com/trustknots/vcknots/wallet/attestation"
	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
	"github.com/trustknots/vcknots/wallet/keystore"
	"github.com/trustknots/vcknots/wallet/profile"
	"github.com/trustknots/vcknots/wallet/receiver"
	"github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// flowTestAuthorizationDetailsTokenResponse is the Section 6.2 Token Response
// to an authorization_details request: an openid_credential entry for
// configurationID with one credential identifier.
func flowTestAuthorizationDetailsTokenResponse(configurationID, identifier string) map[string]any {
	return map[string]any{
		"access_token": "access-1",
		"token_type":   "DPoP",
		"expires_in":   3600,
		"authorization_details": []map[string]any{{
			"type":                        receiverTypes.AuthorizationDetailTypeOpenIDCredential,
			"credential_configuration_id": configurationID,
			"credential_identifiers":      []string{identifier},
		}},
	}
}

// flowTestDecodeAuthorizationDetails decodes an authorization_details form
// parameter.
func flowTestDecodeAuthorizationDetails(t *testing.T, raw string) []map[string]any {
	t.Helper()
	require.NotEmpty(t, raw)
	var details []map[string]any
	require.NoError(t, json.Unmarshal([]byte(raw), &details))
	return details
}

// flowTestUnboundSDJWTVC is an SD-JWT VC signed by issuerKey without cnf.
func flowTestUnboundSDJWTVC(t *testing.T, issuerKey *ecdsa.PrivateKey) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: issuerKey}, (&jose.SignerOptions{}).WithType("dc+sd-jwt"))
	require.NoError(t, err)
	signed, err := jwt.Signed(signer).Claims(map[string]any{
		"iss": "https://issuer.example.test", "vct": "urn:eudi:pid:1",
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	}).Serialize()
	require.NoError(t, err)
	return signed + "~"
}

// flowTestBegin runs BeginIssuance for the fixture's offer.
func flowTestBegin(t *testing.T, fixture *finalIssuanceFixture) *IssuanceAuthorization {
	t.Helper()
	authorization, err := fixture.wallet.BeginIssuance(context.Background(), fixture.issuanceRequest())
	require.NoError(t, err)
	return authorization
}

// flowTestCallback is a redirect to the fixture's redirect_uri with query.
func flowTestCallback(query string) string {
	return fixtureRedirectURI + "?" + query
}

// ---------------------------------------------------------------------------
// Authorization request parameters and wallet-initiated issuance.
// ---------------------------------------------------------------------------

// OpenID4VCI 1.0 Section 5.1.1: with authorization_servers advertised, each
// authorization detail names the Credential Issuer in locations.
func TestIssuanceAuthorizationDetailsCarryLocations(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.tokenResponse = flowTestAuthorizationDetailsTokenResponse("pid", "id-1")
	})
	req := fixture.issuanceRequest()
	req.AuthorizationRequestType = AuthorizationRequestDetails
	_, err := fixture.receive(req)
	require.NoError(t, err)
	details := flowTestDecodeAuthorizationDetails(t, fixture.parForm.Get("authorization_details"))
	require.Len(t, details, 1)
	require.Equal(t, []any{fixture.server.URL}, details[0]["locations"])
}

// OpenID4VCI 1.0 Section 5: without an offer the wallet names the
// configuration, so the request carries no issuer_state and uses its scope.
func TestIssuanceWalletInitiatedUsesRequestedConfiguration(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	result, err := fixture.receive(fixture.walletInitiatedRequest())
	require.NoError(t, err)
	require.Len(t, result.Credentials, 1)
	require.Equal(t, 1, fixture.parCalls)
	require.Empty(t, fixture.parForm.Get("issuer_state"))
	require.Equal(t, "pid-scope", fixture.parForm.Get("scope"))
	require.Empty(t, fixture.parForm.Get("authorization_details"))
}

// With authorization_details the wallet sends the configuration id it
// selected (Section 5.1.1).
func TestIssuanceWalletInitiatedSendsConfigurationID(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.tokenResponse = flowTestAuthorizationDetailsTokenResponse("pid", "id-1")
	})
	req := fixture.walletInitiatedRequest()
	req.AuthorizationRequestType = AuthorizationRequestDetails
	_, err := fixture.receive(req)
	require.NoError(t, err)
	require.Empty(t, fixture.parForm.Get("issuer_state"))
	details := flowTestDecodeAuthorizationDetails(t, fixture.parForm.Get("authorization_details"))
	require.Len(t, details, 1)
	require.Equal(t, "pid", details[0]["credential_configuration_id"])
}

func TestIssuanceWalletInitiatedRequiresIssuerAndConfiguration(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	ctx := context.Background()

	req := fixture.walletInitiatedRequest()
	req.CredentialIssuer = ""
	_, err := fixture.wallet.BeginIssuance(ctx, req)
	require.ErrorIs(t, err, ErrInvalidArgument)
	require.ErrorContains(t, err, "credential issuer is required")

	req = fixture.walletInitiatedRequest()
	req.CredentialConfigurationID = ""
	_, err = fixture.wallet.BeginIssuance(ctx, req)
	require.ErrorIs(t, err, ErrInvalidArgument)
	require.ErrorContains(t, err, "credential configuration ID is required")
	require.Equal(t, 0, fixture.issuerMetadataCalls)
}

// An offer names the issuer, so CredentialIssuer must be empty with one, and
// CredentialConfigurationID can only select a configuration the offer lists.
func TestIssuanceOfferRestrictsRequestFields(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	ctx := context.Background()

	req := fixture.issuanceRequest()
	req.CredentialIssuer = fixture.server.URL
	_, err := fixture.wallet.BeginIssuance(ctx, req)
	require.ErrorIs(t, err, ErrInvalidArgument)
	require.ErrorContains(t, err, "must be empty when a credential offer is provided")

	req = fixture.issuanceRequest()
	req.CredentialConfigurationID = "not-offered"
	_, err = fixture.wallet.BeginIssuance(ctx, req)
	require.ErrorIs(t, err, ErrInvalidArgument)
	require.ErrorIs(t, err, ErrUnknownCredentialConfiguration)
	require.Equal(t, 0, fixture.issuerMetadataCalls)

	req = fixture.issuanceRequest()
	req.CredentialConfigurationID = "pid"
	authorization, err := fixture.wallet.BeginIssuance(ctx, req)
	require.NoError(t, err)
	require.Equal(t, "pid", authorization.CredentialConfigurationID)
}

// ---------------------------------------------------------------------------
// The acceptance policy is required before anything is sent or stored.
// ---------------------------------------------------------------------------

// The 1.0 flow must authenticate the credential it receives, so a wallet
// without Config.CredentialAcceptance fails at the first stage.
func TestIssuanceFailsWithoutAcceptancePolicy(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.noAcceptancePolicy = true
	})

	result, err := fixture.receive(fixture.issuanceRequest())
	require.ErrorIs(t, err, ErrCredentialAcceptancePolicyRequired)
	require.Nil(t, result)
	require.Equal(t, 0, fixture.issuerMetadataCalls)
	entries, _, listErr := fixture.wallet.GetCredentialEntries(GetCredentialEntriesRequest{})
	require.NoError(t, listErr)
	require.Empty(t, entries)
}

// Every later stage checks the policy too, so a state resumed in a wallet
// without one sends nothing.
func TestIssuanceLaterStagesFailWithoutAcceptancePolicy(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.includeDeferredEndpoint = true
		f.credentialHandler = func(w http.ResponseWriter, _ *http.Request) {
			mockserver.JSONResponse(w, http.StatusAccepted, map[string]any{"transaction_id": "tx-1"})
		}
	})
	ctx := context.Background()
	authorization := flowTestBegin(t, fixture)
	location, err := fixture.followAuthorization(authorization)
	require.NoError(t, err)
	grant, err := fixture.wallet.AuthorizeIssuance(ctx, authorization, location)
	require.NoError(t, err)
	result, err := fixture.wallet.RequestCredential(ctx, grant, fixture.credentialRequest())
	require.NoError(t, err)
	require.NotNil(t, result.Deferred)

	fixture.noAcceptancePolicy = true
	unprotected := fixture.newWallet(t)
	tokenCalls, credentialCalls := fixture.tokenCalls, fixture.credentialCalls

	_, err = unprotected.AuthorizeIssuance(ctx, authorization, location)
	require.ErrorIs(t, err, ErrCredentialAcceptancePolicyRequired)
	_, err = unprotected.RequestCredential(ctx, grant, fixture.credentialRequest())
	require.ErrorIs(t, err, ErrCredentialAcceptancePolicyRequired)
	_, err = unprotected.RequestDeferredCredential(ctx, result.Deferred)
	require.ErrorIs(t, err, ErrCredentialAcceptancePolicyRequired)

	require.Equal(t, tokenCalls, fixture.tokenCalls)
	require.Equal(t, credentialCalls, fixture.credentialCalls)
	require.Equal(t, 0, fixture.deferredCalls)
	entries, _, listErr := unprotected.GetCredentialEntries(GetCredentialEntriesRequest{})
	require.NoError(t, listErr)
	require.Empty(t, entries)
}

// ---------------------------------------------------------------------------
// Unknown credential configurations.
// ---------------------------------------------------------------------------

// Section 12.2.4: credential_configurations_supported names every
// configuration the issuer offers, so an absent one fails before the
// authorization request.
func TestIssuanceRejectsUnknownConfigurationID(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	req := fixture.walletInitiatedRequest()
	req.CredentialConfigurationID = "not-offered"

	_, err := fixture.wallet.BeginIssuance(context.Background(), req)
	require.ErrorIs(t, err, ErrUnknownCredentialConfiguration)
	require.Equal(t, 0, fixture.parCalls)
	require.Equal(t, 0, fixture.authorizeCalls)
	require.Equal(t, 0, fixture.credentialCalls)
}

func TestIssuanceAcceptsOfferedConfigurationID(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	result, err := fixture.receive(fixture.walletInitiatedRequest())
	require.NoError(t, err)
	require.Len(t, result.Credentials, 1)
	require.Equal(t, 1, fixture.parCalls)
}

// ---------------------------------------------------------------------------
// PAR and HAIP scope rules.
// ---------------------------------------------------------------------------

// HAIP Section 4 requires PAR; OpenID4VCI 1.0 does not, so without a
// pushed_authorization_request_endpoint the parameters travel inline.
func TestIssuanceWithoutPAR(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.omitPAREndpoint = true
	})
	result, err := fixture.receive(fixture.issuanceRequest())
	require.NoError(t, err)
	require.Len(t, result.Credentials, 1)
	require.Equal(t, 0, fixture.parCalls)
	require.Equal(t, 1, fixture.authorizeCalls)
	query := fixture.authorizeQuery
	require.Equal(t, "code", query.Get("response_type"))
	require.Equal(t, "client-1", query.Get("client_id"))
	require.Equal(t, fixtureRedirectURI, query.Get("redirect_uri"))
	require.Equal(t, "pid-scope", query.Get("scope"))
	require.Equal(t, "S256", query.Get("code_challenge_method"))
	require.NotEmpty(t, query.Get("code_challenge"))
	require.NotEmpty(t, query.Get("state"))
	require.Equal(t, "issuer-state-1", query.Get("issuer_state"))
	require.Empty(t, query.Get("request_uri"))
}

func TestIssuanceHAIPRequiresPAR(t *testing.T) {
	fixture := newHAIPIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.omitPAREndpoint = true
	})
	_, err := fixture.wallet.BeginIssuance(context.Background(), fixture.issuanceRequest())
	require.ErrorIs(t, err, receiverTypes.ErrInvalidMetadata)
	require.ErrorContains(t, err, "HAIP requires a pushed authorization request endpoint")
	require.Equal(t, 0, fixture.authorizeCalls)
}

// HAIP Sections 4.1 and 4.2: the wallet requests the Credential Type with the
// scope the configuration advertises.
func TestIssuanceHAIPAuthorizationRequestUsesScope(t *testing.T) {
	fixture := newHAIPIssuanceFixture(t)
	flowTestBegin(t, fixture)
	require.Equal(t, "pid-scope", fixture.parForm.Get("scope"))
	require.Empty(t, fixture.parForm.Get("authorization_details"))
}

func TestIssuanceHAIPAuthorizationRequestRejectsAuthorizationDetails(t *testing.T) {
	fixture := newHAIPIssuanceFixture(t)
	req := fixture.issuanceRequest()
	req.AuthorizationRequestType = AuthorizationRequestDetails
	_, err := fixture.wallet.BeginIssuance(context.Background(), req)
	require.ErrorIs(t, err, ErrInvalidArgument)
	require.ErrorContains(t, err, "HAIP requires the scope authorization request type")
	require.Equal(t, 0, fixture.parCalls)
}

// A configuration without a scope cannot be requested under HAIP. The HAIP
// metadata validation of the receiver plugin refuses it earlier, so the rule
// is asserted on the function that builds the parameters.
func TestIssuanceHAIPAuthorizationRequestRejectsScopelessConfiguration(t *testing.T) {
	scopeless := receiverTypes.CredentialConfiguration{Format: "dc+sd-jwt"}
	for _, requested := range []AuthorizationRequestType{"", AuthorizationRequestScope} {
		_, _, err := authorizationRequestParameters(requested, "pid", scopeless, true)
		require.ErrorIs(t, err, receiverTypes.ErrInvalidMetadata)
		require.ErrorContains(t, err, `HAIP requires the credential configuration "pid" to advertise a scope`)
	}

	// Outside HAIP the default falls back to authorization_details (Section
	// 12.2.4).
	scope, details, err := authorizationRequestParameters("", "pid", scopeless, false)
	require.NoError(t, err)
	require.Empty(t, scope)
	require.Len(t, details, 1)
}

// Outside HAIP both request types remain (Section 5.1.1), and the Credential
// Request names the credential_identifier the Token Response returned.
func TestIssuanceFinalAllowsAuthorizationDetails(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.tokenResponse = flowTestAuthorizationDetailsTokenResponse("pid", "id-1")
	})
	req := fixture.issuanceRequest()
	req.AuthorizationRequestType = AuthorizationRequestDetails
	_, err := fixture.receive(req)
	require.NoError(t, err)
	require.Empty(t, fixture.parForm.Get("scope"))
	details := flowTestDecodeAuthorizationDetails(t, fixture.parForm.Get("authorization_details"))
	require.Len(t, details, 1)
	require.Equal(t, "pid", details[0]["credential_configuration_id"])
	require.Equal(t, "id-1", fixture.lastCredentialBody["credential_identifier"])
	require.NotContains(t, fixture.lastCredentialBody, "credential_configuration_id")
}

// ---------------------------------------------------------------------------
// Deferred issuance and response encryption.
// ---------------------------------------------------------------------------

// Section 9.1: the Deferred Credential Request repeats
// credential_response_encryption, with the key of the Credential Request,
// and Section 8.1 then requires the request itself to be encrypted.
func TestIssuanceDeferredRequestCarriesResponseEncryption(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.includeDeferredEndpoint = true
		f.responseEncryption = true
		f.encryptionRequired = true
		f.requestEncryption = true
		f.credentialHandler = func(w http.ResponseWriter, _ *http.Request) {
			writeObservedFinalCredentialResponse(f.obs, w, f.responseKeyFromRequest(), map[string]any{"transaction_id": "tx-1"})
		}
	})
	ctx := context.Background()
	result, err := fixture.receive(fixture.issuanceRequest())
	require.NoError(t, err)
	require.NotNil(t, result.Deferred)
	require.NotNil(t, result.Deferred.ResponseDecryptionKey)
	credentialEncryption, ok := fixture.lastCredentialBody["credential_response_encryption"].(map[string]any)
	require.True(t, ok)

	issued, err := fixture.wallet.RequestDeferredCredential(ctx, result.Deferred)
	require.NoError(t, err)
	require.Len(t, issued.Credentials, 1)
	require.Equal(t, "tx-1", fixture.lastDeferredBody["transaction_id"])
	encryption, ok := fixture.lastDeferredBody["credential_response_encryption"].(map[string]any)
	require.True(t, ok, "deferred request is missing credential_response_encryption: %#v", fixture.lastDeferredBody)
	require.NotNil(t, encryption["jwk"])
	require.Equal(t, "A128GCM", encryption["enc"])
	require.Equal(t, credentialEncryption["jwk"], encryption["jwk"])
}

func TestIssuanceDeferredRequestOmitsEncryptionWhenNotRequested(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.includeDeferredEndpoint = true
		f.credentialHandler = func(w http.ResponseWriter, _ *http.Request) {
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{"transaction_id": "tx-1"})
		}
	})
	result, err := fixture.receive(fixture.issuanceRequest())
	require.NoError(t, err)
	require.NotNil(t, result.Deferred)
	require.Nil(t, result.Deferred.ResponseDecryptionKey)

	issued, err := fixture.wallet.RequestDeferredCredential(context.Background(), result.Deferred)
	require.NoError(t, err)
	require.Len(t, issued.Credentials, 1)
	require.Equal(t, "tx-1", fixture.lastDeferredBody["transaction_id"])
	require.NotContains(t, fixture.lastDeferredBody, "credential_response_encryption")
}

// Section 9.2 puts no bound on the interval; the wallet reports it as the
// issuer named it and makes one request per call.
func TestIssuanceDeferredReportsIssuerInterval(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.includeDeferredEndpoint = true
		f.credentialHandler = func(w http.ResponseWriter, _ *http.Request) {
			mockserver.JSONResponse(w, http.StatusAccepted, map[string]any{"transaction_id": "tx-1", "interval": 3600})
		}
		f.deferredHandler = func(w http.ResponseWriter, _ *http.Request) {
			mockserver.JSONResponse(w, http.StatusBadRequest, map[string]any{"error": "issuance_pending", "interval": 7200})
		}
	})
	ctx := context.Background()
	result, err := fixture.receive(fixture.issuanceRequest())
	require.NoError(t, err)
	require.NotNil(t, result.Deferred)
	require.Equal(t, time.Hour, result.Deferred.Interval)
	require.Equal(t, 0, fixture.deferredCalls)

	pending, err := fixture.wallet.RequestDeferredCredential(ctx, result.Deferred)
	require.NoError(t, err)
	require.Empty(t, pending.Credentials)
	require.NotNil(t, pending.Deferred)
	require.Equal(t, "tx-1", pending.Deferred.TransactionID)
	require.Equal(t, 2*time.Hour, pending.Deferred.Interval)
	require.Equal(t, 1, fixture.deferredCalls)

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	_, err = fixture.wallet.RequestDeferredCredential(cancelled, pending.Deferred)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, 1, fixture.deferredCalls)
}

// ---------------------------------------------------------------------------
// Contexts.
// ---------------------------------------------------------------------------

// A cancelled context stops a stage before it sends anything.
func TestIssuanceStagesHonourACancelledContext(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := fixture.wallet.BeginIssuance(cancelled, fixture.issuanceRequest())
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, 0, fixture.issuerMetadataCalls)

	authorization := flowTestBegin(t, fixture)
	location, err := fixture.followAuthorization(authorization)
	require.NoError(t, err)
	_, err = fixture.wallet.AuthorizeIssuance(cancelled, authorization, location)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, 0, fixture.tokenCalls)

	grant, err := fixture.wallet.AuthorizeIssuance(context.Background(), authorization, location)
	require.NoError(t, err)
	_, err = fixture.wallet.RequestCredential(cancelled, grant, fixture.credentialRequest())
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, 0, fixture.credentialCalls)
}

// With a live context every stage runs: PAR, token, nonce, credential and,
// when the caller asks, the Section 11 notification.
func TestIssuanceBoundToALiveContextCompletes(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.includeNotification = true
	})
	result, err := fixture.receive(fixture.issuanceRequest())
	require.NoError(t, err)
	require.Len(t, result.Credentials, 1)
	require.Equal(t, 1, fixture.parCalls)
	require.Equal(t, 1, fixture.tokenCalls)
	require.Equal(t, 1, fixture.nonceCalls)
	require.Equal(t, 1, fixture.credentialCalls)
	require.NotNil(t, result.Notification)
	require.NoError(t, fixture.wallet.NotifyIssuer(context.Background(), result.Notification, NotificationCredentialAccepted, ""))
	require.Equal(t, []string{"credential_accepted"}, fixture.notificationEvents)
}

// The context reaches the HTTP request itself: the Credential Endpoint blocks
// until the test cancels from inside the handler, so only a request bound to
// the context can fail then.
func TestIssuanceContextCancelsARequestInFlight(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var credentialRequests atomic.Int32
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.credentialHandler = func(_ http.ResponseWriter, r *http.Request) {
			credentialRequests.Add(1)
			cancel()
			<-r.Context().Done()
		}
	})
	grant, err := fixture.authorize(fixture.issuanceRequest())
	require.NoError(t, err)

	result, err := fixture.wallet.RequestCredential(ctx, grant, fixture.credentialRequest())
	require.Nil(t, result)
	require.ErrorIs(t, err, context.Canceled)
	require.Contains(t, err.Error(), "failed to receive credential")
	require.Equal(t, int32(1), credentialRequests.Load())
}

// ---------------------------------------------------------------------------
// The authorization code flow splits around a browser.
// ---------------------------------------------------------------------------

func TestBeginIssuanceReturnsResumableState(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	before := time.Now()
	authorization := flowTestBegin(t, fixture)
	require.Equal(t, 1, fixture.parCalls)
	require.Equal(t, 0, fixture.authorizeCalls)

	authorizationURL, err := url.Parse(authorization.AuthorizationURL)
	require.NoError(t, err)
	require.Equal(t, "client-1", authorizationURL.Query().Get("client_id"))
	require.Equal(t, "urn:request:1", authorizationURL.Query().Get("request_uri"))
	require.Equal(t, fixture.pushedState, authorization.State)
	require.NotEmpty(t, authorization.CodeVerifier)
	require.Equal(t, IssuanceVersionFinal, authorization.Version)
	require.Equal(t, "pid", authorization.CredentialConfigurationID)
	require.False(t, authorization.RequestURIExpiresAt.Before(before.Add(time.Minute)))
	require.False(t, authorization.RequestURIExpiresAt.After(time.Now().Add(time.Minute)))

	var restored IssuanceAuthorization
	requireJSONRoundTrip(t, authorization, &restored)
	require.Equal(t, authorization.State, restored.State)
	require.Equal(t, authorization.CodeVerifier, restored.CodeVerifier)
	require.Equal(t, authorization.AuthorizationURL, restored.AuthorizationURL)
	require.True(t, authorization.RequestURIExpiresAt.Equal(restored.RequestURIExpiresAt))
	require.Equal(t, fixture.server.URL, restored.CredentialIssuer)
	require.Equal(t, fixture.server.URL, restored.AuthorizationServer)
	require.Equal(t, "client-1", restored.ClientID)
	require.Equal(t, fixtureRedirectURI, restored.RedirectURI)

	ctx := context.Background()
	grant, err := fixture.wallet.AuthorizeIssuance(ctx, &restored, flowTestCallback("code=code-1&state="+url.QueryEscape(restored.State)))
	require.NoError(t, err)
	result, err := fixture.wallet.RequestCredential(ctx, grant, fixture.credentialRequest())
	require.NoError(t, err)
	require.Len(t, result.Credentials, 1)
	// The library never drove the authorization endpoint.
	require.Equal(t, 0, fixture.authorizeCalls)
	require.Equal(t, "code-1", fixture.tokenForms[0].Get("code"))
}

// A state that no longer fits the wallet or the issuer is refused before the
// token request.
func TestAuthorizeIssuanceRejectsTamperedState(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	authorization := flowTestBegin(t, fixture)
	redirect := flowTestCallback("code=code-1&state=" + url.QueryEscape(authorization.State))

	for name, tamper := range map[string]func(*IssuanceAuthorization){
		"authorization server": func(a *IssuanceAuthorization) { a.AuthorizationServer = "https://as.attacker.example" },
		"client_id":            func(a *IssuanceAuthorization) { a.ClientID = "client-2" },
		"redirect_uri":         func(a *IssuanceAuthorization) { a.RedirectURI = "https://attacker.example/callback" },
		"missing verifier":     func(a *IssuanceAuthorization) { a.CodeVerifier = "" },
	} {
		t.Run(name, func(t *testing.T) {
			var tampered IssuanceAuthorization
			requireJSONRoundTrip(t, authorization, &tampered)
			tamper(&tampered)
			_, err := fixture.wallet.AuthorizeIssuance(context.Background(), &tampered, redirect)
			require.ErrorIs(t, err, ErrIssuanceStateMismatch)
		})
	}
	require.Equal(t, 0, fixture.tokenCalls)
}

func TestAuthorizeIssuanceRejectsStateMismatch(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	authorization := flowTestBegin(t, fixture)

	_, err := fixture.wallet.AuthorizeIssuance(context.Background(), authorization, flowTestCallback("code=code-1&state=someone-elses-state"))
	require.ErrorIs(t, err, ErrAuthorizationStateMismatch)
	require.Equal(t, 0, fixture.tokenCalls)
}

// RFC 9207 Section 2.4: when the server advertises
// authorization_response_iss_parameter_supported, iss must be present.
func TestAuthorizeIssuanceRejectsMissingIssuerParameter(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.issParameterSupported = true
	})
	authorization := flowTestBegin(t, fixture)

	_, err := fixture.wallet.AuthorizeIssuance(context.Background(), authorization, flowTestCallback("code=code-1&state="+url.QueryEscape(authorization.State)))
	require.ErrorIs(t, err, ErrAuthorizationIssMissing)
	require.Equal(t, 0, fixture.tokenCalls)
}

func TestAuthorizeIssuanceReturnsAuthorizationError(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	authorization := flowTestBegin(t, fixture)

	_, err := fixture.wallet.AuthorizeIssuance(context.Background(), authorization,
		flowTestCallback("error=access_denied&error_description=user%20said%20no&state="+url.QueryEscape(authorization.State)))
	var authorizationError *AuthorizationResponseError
	require.ErrorAs(t, err, &authorizationError)
	require.Equal(t, "access_denied", authorizationError.Code)
	require.Equal(t, "user said no", authorizationError.Description)
	require.Equal(t, authorization.State, authorizationError.State)
	code, ok := ErrorCode(err)
	require.True(t, ok)
	require.Equal(t, "authorization_error_response", code)
	require.Equal(t, 0, fixture.tokenCalls)
}

// RFC 6749 Sections 4.1.2.1 and 10.12: an error redirect without this
// request's state is a forgery and does not abort the issuance.
func TestAuthorizeIssuanceIgnoresErrorRedirectWithoutState(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	authorization := flowTestBegin(t, fixture)

	for name, redirect := range map[string]string{
		"missing state": flowTestCallback("error=access_denied&error_description=attacker%20text"),
		"foreign state": flowTestCallback("error=access_denied&state=someone-elses-state"),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := fixture.wallet.AuthorizeIssuance(context.Background(), authorization, redirect)
			require.ErrorIs(t, err, ErrAuthorizationStateMismatch)
			var authorizationError *AuthorizationResponseError
			require.False(t, errors.As(err, &authorizationError))
		})
	}
	require.Equal(t, 0, fixture.tokenCalls)

	// The genuine redirect still completes the authorization.
	location, err := fixture.followAuthorization(authorization)
	require.NoError(t, err)
	_, err = fixture.wallet.AuthorizeIssuance(context.Background(), authorization, location)
	require.NoError(t, err)
}

// RFC 9207 Section 2.4 applies iss to error responses too.
func TestAuthorizeIssuanceChecksIssuerOnErrorRedirect(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.issParameterSupported = true
	})
	authorization := flowTestBegin(t, fixture)
	ctx := context.Background()
	state := url.QueryEscape(authorization.State)

	_, err := fixture.wallet.AuthorizeIssuance(ctx, authorization, flowTestCallback("error=access_denied&state="+state))
	require.ErrorIs(t, err, ErrAuthorizationIssMissing)

	_, err = fixture.wallet.AuthorizeIssuance(ctx, authorization,
		flowTestCallback("error=access_denied&state="+state+"&iss="+url.QueryEscape("https://attacker.example")))
	require.ErrorIs(t, err, ErrAuthorizationIssMismatch)

	_, err = fixture.wallet.AuthorizeIssuance(ctx, authorization,
		flowTestCallback("error=access_denied&state="+state+"&iss="+url.QueryEscape(fixture.server.URL)))
	var authorizationError *AuthorizationResponseError
	require.ErrorAs(t, err, &authorizationError)
	require.Equal(t, 0, fixture.tokenCalls)
}

// A callback delivered anywhere but the registered redirect_uri is not this
// request's authorization response.
func TestAuthorizeIssuanceRejectsForeignRedirectURI(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	authorization := flowTestBegin(t, fixture)

	_, err := fixture.wallet.AuthorizeIssuance(context.Background(), authorization,
		"openid-credential-offer://elsewhere?code=code-1&state="+url.QueryEscape(authorization.State))
	require.ErrorIs(t, err, ErrAuthorizationRedirectURIMismatch)
	require.Equal(t, 0, fixture.tokenCalls)
}

// A redirect with neither an error nor a code leaves nothing to exchange.
func TestAuthorizeIssuanceRejectsMissingCode(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	authorization := flowTestBegin(t, fixture)

	_, err := fixture.wallet.AuthorizeIssuance(context.Background(), authorization, flowTestCallback("state="+url.QueryEscape(authorization.State)))
	require.ErrorIs(t, err, ErrAuthorizationCodeMissing)
	require.Equal(t, 0, fixture.tokenCalls)
}

// The authorization stages carry no holder key, so a wallet that creates the
// key after the browser returned can still authorize; the credential stage
// needs it for the key proofs.
func TestIssuanceHolderKeyIsOnlyNeededForTheCredentialRequest(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	grant, err := fixture.authorize(fixture.issuanceRequest())
	require.NoError(t, err)
	require.Equal(t, 1, fixture.tokenCalls)

	_, err = fixture.wallet.RequestCredential(context.Background(), grant, CredentialRequest{})
	require.ErrorIs(t, err, ErrInvalidArgument)
	require.ErrorContains(t, err, "holder key is required")
	require.Equal(t, 0, fixture.credentialCalls)

	result, err := fixture.wallet.RequestCredential(context.Background(), grant, fixture.credentialRequest())
	require.NoError(t, err)
	require.Len(t, result.Credentials, 1)
}

// RFC 9126 Section 2.2: the request_uri lifetime bounds opening the
// authorization URL. No stated lifetime is not an expiry the wallet invents.
func TestIssuanceAuthorizationRequestURIExpiry(t *testing.T) {
	expiry := time.Now().Add(time.Minute)
	authorization := &IssuanceAuthorization{RequestURIExpiresAt: expiry}
	require.False(t, authorization.RequestURIExpired(expiry.Add(-time.Second)))
	require.True(t, authorization.RequestURIExpired(expiry))
	require.True(t, authorization.RequestURIExpired(expiry.Add(time.Second)))
	require.False(t, (&IssuanceAuthorization{}).RequestURIExpired(time.Now()))
	require.False(t, (*IssuanceAuthorization)(nil).RequestURIExpired(time.Now()))

	withoutLifetime := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.parExpiresIn = 0
	})
	require.True(t, flowTestBegin(t, withoutLifetime).RequestURIExpiresAt.IsZero())

	withoutPAR := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.omitPAREndpoint = true
	})
	require.True(t, flowTestBegin(t, withoutPAR).RequestURIExpiresAt.IsZero())

	// The redirect may arrive after the request_uri expired.
	fixture := newFinalIssuanceFixture(t)
	pushed := flowTestBegin(t, fixture)
	location, err := fixture.followAuthorization(pushed)
	require.NoError(t, err)
	pushed.RequestURIExpiresAt = time.Now().Add(-time.Second)
	_, err = fixture.wallet.AuthorizeIssuance(context.Background(), pushed, location)
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Holder binding.
// ---------------------------------------------------------------------------

// Section 12.2.4: cryptographic_binding_methods_supported means the credential
// is bound to a key, so one without cnf is refused, not stored, and the
// caller can report credential_failure.
func TestIssuanceRefusesUnboundCredentialWhenBindingIsRequired(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.includeNotification = true
		f.bindingMethods = []string{"jwk"}
		f.proofTypesSupported = map[string]any{
			"jwt": map[string]any{"proof_signing_alg_values_supported": []string{"ES256"}},
		}
		f.credentialHandler = func(w http.ResponseWriter, _ *http.Request) {
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{
				"credentials":     []any{map[string]any{"credential": flowTestUnboundSDJWTVC(f.t, f.issuerKey)}},
				"notification_id": "notification-1",
			})
		}
	})
	result, err := fixture.receive(fixture.issuanceRequest())
	require.ErrorIs(t, err, acceptance.ErrHolderBindingMissing)
	require.NotNil(t, result)
	require.Empty(t, result.Credentials)
	require.NotNil(t, result.Notification)
	require.Empty(t, fixture.notificationEvents)

	require.NoError(t, fixture.wallet.NotifyIssuer(context.Background(), result.Notification, NotificationCredentialFailure, ""))
	require.Equal(t, []string{"credential_failure"}, fixture.notificationEvents)
	entries, _, err := fixture.wallet.GetCredentialEntries(GetCredentialEntriesRequest{})
	require.NoError(t, err)
	require.Empty(t, entries)
}

// Without cryptographic_binding_methods_supported a credential without cnf is
// accepted.
func TestIssuanceAcceptsUnboundCredentialWhenBindingIsNotRequired(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.credentialHandler = func(w http.ResponseWriter, _ *http.Request) {
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{
				"credentials": []any{map[string]any{"credential": flowTestUnboundSDJWTVC(f.t, f.issuerKey)}},
			})
		}
	})
	result, err := fixture.receive(fixture.issuanceRequest())
	require.NoError(t, err)
	require.Len(t, result.Credentials, 1)
}

// ---------------------------------------------------------------------------
// Proof type and algorithm.
// ---------------------------------------------------------------------------

// Section 12.2.4.1: a configuration that lists proof types but not jwt is
// refused before any request leaves the wallet.
func TestIssuanceRefusesConfigurationWithoutJWTProofType(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.proofTypesSupported = map[string]any{
			"attestation": map[string]any{"proof_signing_alg_values_supported": []string{"ES256"}},
		}
	})
	_, err := fixture.wallet.BeginIssuance(context.Background(), fixture.issuanceRequest())
	require.ErrorIs(t, err, ErrProofTypeUnsupported)
	require.Equal(t, 0, fixture.parCalls)
	require.Equal(t, 0, fixture.credentialCalls)
}

// Appendix F.1: the key proof's alg must be one of
// proof_signing_alg_values_supported; a holder key that cannot sign one is
// refused before the Credential Request.
func TestIssuanceRefusesHolderKeyWithUnlistedAlgorithm(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.proofTypesSupported = map[string]any{
			"jwt": map[string]any{"proof_signing_alg_values_supported": []string{"ES384"}},
		}
	})
	_, err := fixture.receive(fixture.issuanceRequest())
	require.ErrorIs(t, err, ErrProofAlgorithmNotSupported)
	require.Equal(t, 0, fixture.credentialCalls)
}

// Appendix F.1: the key attestation's alg is held to the same list.
func TestIssuanceRefusesKeyAttestationWithUnlistedAlgorithm(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	attesterKey := jose.JSONWebKey{Key: privateKey, KeyID: "key-attester-p384", Algorithm: string(jose.ES384), Use: "sig"}
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.keyAttestationsRequired = true
		f.keyAttestation = &attestation.StaticKeyAttester{Key: testKeyEntry(t, attesterKey), Issuer: "https://key-attester.example"}
	})

	_, err = fixture.receive(fixture.issuanceRequest())
	require.ErrorIs(t, err, ErrProofAlgorithmNotSupported)
	require.Equal(t, 0, fixture.credentialCalls)
}

// ---------------------------------------------------------------------------
// Receiver plugins.
// ---------------------------------------------------------------------------

// flowTestTransportOnlyPlugin implements the OpenID4VCI 1.0 transport and
// nothing else, as a plugin written outside this module may.
type flowTestTransportOnlyPlugin struct {
	receiverTypes.Receiver
	receiverTypes.OID4VCITransport
}

// A receiver plugin that only speaks HTTP is enough for a whole issuance: the
// wallet signs the DPoP and key proofs with its own keys.
func TestIssuanceAcceptsTransportOnlyPlugin(t *testing.T) {
	var registered receiverTypes.Receiver
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.wrapReceiverPlugin = func(plugin receiverTypes.Receiver) receiverTypes.Receiver {
			transport, ok := plugin.(receiverTypes.OID4VCITransport)
			require.True(t, ok)
			registered = &flowTestTransportOnlyPlugin{Receiver: plugin, OID4VCITransport: transport}
			return registered
		}
	})
	_, isValidator := registered.(oid4vciProfileValidator)
	require.False(t, isValidator)
	_, isCarrier := registered.(profile.Carrier)
	require.False(t, isCarrier)

	result, err := fixture.receive(fixture.issuanceRequest())
	require.NoError(t, err)
	require.Len(t, result.Credentials, 1)
	require.NotEmpty(t, fixture.tokenHeaders.Get("DPoP"))
	claims := finalProofClaims(t, fixture.proofJWTs(t)[0])
	require.Equal(t, fixture.server.URL, claims["aud"])
}

// ---------------------------------------------------------------------------
// Selection helpers.
// ---------------------------------------------------------------------------

// Appendix D: key_attestations_required is the signal whenever present, even
// as an empty object.
func TestIssuerRequiresKeyAttestation(t *testing.T) {
	withProof := func(proof receiverTypes.ProofType) receiverTypes.CredentialConfiguration {
		return receiverTypes.CredentialConfiguration{ProofTypesSupported: &map[string]receiverTypes.ProofType{"jwt": proof}}
	}
	require.True(t, issuerRequiresKeyAttestation(withProof(receiverTypes.ProofType{KeyAttestationsRequired: &receiverTypes.KeyAttestationsRequired{}})))
	require.False(t, issuerRequiresKeyAttestation(withProof(receiverTypes.ProofType{})))
	require.False(t, issuerRequiresKeyAttestation(receiverTypes.CredentialConfiguration{}))
}

// The grant records whether the requested configuration requires a key
// attestation.
func TestIssuanceGrantRecordsKeyAttestationRequirement(t *testing.T) {
	plain := newFinalIssuanceFixture(t)
	grant, err := plain.authorize(plain.issuanceRequest())
	require.NoError(t, err)
	require.False(t, grant.KeyAttestationRequired)

	required := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.keyAttestationsRequired = true
	})
	grant, err = required.authorize(required.issuanceRequest())
	require.NoError(t, err)
	require.True(t, grant.KeyAttestationRequired)
}

// Section 4.1.1: the grant's authorization_server must be one of the issuer
// metadata's authorization_servers; without a hint the first listed server is
// used, or the issuer itself when none is listed.
func TestOfferedAuthorizationServer(t *testing.T) {
	uri := func(t *testing.T, raw string) common.URIField {
		t.Helper()
		parsed, err := common.ParseURIField(raw)
		require.NoError(t, err)
		return *parsed
	}
	first := uri(t, "https://as.example/")
	second := uri(t, "https://other.example/")
	issuer := uri(t, "https://issuer.example/")
	metadata := &receiverTypes.CredentialIssuerMetadata{AuthorizationServers: []common.URIField{first, second}}

	t.Run("grant-hint-that-is-listed", func(t *testing.T) {
		got, err := offeredAuthorizationServer("https://other.example/")(metadata, issuer)
		require.NoError(t, err)
		require.Equal(t, second.String(), got.String())
	})
	t.Run("grant-hint-that-is-not-listed", func(t *testing.T) {
		_, err := offeredAuthorizationServer("https://unlisted.example/")(metadata, issuer)
		require.ErrorIs(t, err, receiverTypes.ErrInvalidMetadata)
	})
	t.Run("no-hint-selects-the-first-listed", func(t *testing.T) {
		got, err := offeredAuthorizationServer("")(metadata, issuer)
		require.NoError(t, err)
		require.Equal(t, first.String(), got.String())
	})
	t.Run("no-listed-servers-falls-back-to-the-issuer", func(t *testing.T) {
		got, err := offeredAuthorizationServer("")(&receiverTypes.CredentialIssuerMetadata{}, issuer)
		require.NoError(t, err)
		require.Equal(t, issuer.String(), got.String())
	})
}

// A grant hint the issuer metadata does not list stops the issuance before
// the authorization server is contacted.
func TestIssuanceRejectsUnlistedAuthorizationServerHint(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	req := fixture.issuanceRequest()
	req.CredentialOffer.Grants["authorization_code"].AuthorizationServer = "https://unlisted.example"

	_, err := fixture.wallet.BeginIssuance(context.Background(), req)
	require.ErrorIs(t, err, receiverTypes.ErrInvalidMetadata)
	require.Equal(t, 0, fixture.asMetadataCalls)
	require.Equal(t, 0, fixture.parCalls)
}

// ---------------------------------------------------------------------------
// authorization_details modes (Section 6.2).
// ---------------------------------------------------------------------------

func flowTestOpenIDCredentialDetail(configurationID string, identifiers ...string) receiverTypes.CredentialIssuanceAuthorizationDetail {
	return receiverTypes.CredentialIssuanceAuthorizationDetail{
		Type:                      receiverTypes.AuthorizationDetailTypeOpenIDCredential,
		CredentialConfigurationID: configurationID,
		CredentialIdentifiers:     identifiers,
	}
}

// After an authorization_details request the Token Response must carry a
// usable openid_credential entry for the configuration: a missing entry, a
// foreign configuration, no identifiers or more than one fail closed.
func TestCredentialIdentifiersRequiredModeRejectsUnusableResponses(t *testing.T) {
	cases := map[string]*receiverTypes.CredentialIssuanceAccessToken{
		"no access token":                 nil,
		"missing authorization_details":   {Token: "access-1"},
		"foreign configuration":           {Token: "access-1", AuthorizationDetails: []receiverTypes.CredentialIssuanceAuthorizationDetail{flowTestOpenIDCredentialDetail("other", "id-other")}},
		"empty credential_identifiers":    {Token: "access-1", AuthorizationDetails: []receiverTypes.CredentialIssuanceAuthorizationDetail{flowTestOpenIDCredentialDetail("pid")}},
		"blank credential_identifiers":    {Token: "access-1", AuthorizationDetails: []receiverTypes.CredentialIssuanceAuthorizationDetail{flowTestOpenIDCredentialDetail("pid", " ")}},
		"multiple credential_identifiers": {Token: "access-1", AuthorizationDetails: []receiverTypes.CredentialIssuanceAuthorizationDetail{flowTestOpenIDCredentialDetail("pid", "id-1", "id-2")}},
	}
	for name, accessToken := range cases {
		t.Run(name, func(t *testing.T) {
			identifiers, err := credentialIdentifiersFor(accessToken, "pid", authorizationDetailsRequired)
			require.ErrorIs(t, err, ErrAuthorizationDetailsMissing)
			require.Nil(t, identifiers)
		})
	}
}

func TestCredentialIdentifiersRequiredModeSelectsMatchingEntry(t *testing.T) {
	accessToken := &receiverTypes.CredentialIssuanceAccessToken{
		Token: "access-1",
		AuthorizationDetails: []receiverTypes.CredentialIssuanceAuthorizationDetail{
			flowTestOpenIDCredentialDetail("other", "id-other"),
			flowTestOpenIDCredentialDetail("pid", "id-1"),
		},
	}
	identifiers, err := credentialIdentifiersFor(accessToken, "pid", authorizationDetailsRequired)
	require.NoError(t, err)
	require.Equal(t, []string{"id-1"}, identifiers)
}

// After a scope request the member is optional (Section 6.2), so its absence
// names the configuration. A foreign entry is still no substitute, since
// credential_identifiers belong to their own entry.
func TestCredentialIdentifiersOptionalMode(t *testing.T) {
	t.Run("missing authorization_details is accepted", func(t *testing.T) {
		identifiers, err := credentialIdentifiersFor(&receiverTypes.CredentialIssuanceAccessToken{Token: "access-1"}, "pid", authorizationDetailsOptional)
		require.NoError(t, err)
		require.Nil(t, identifiers)
	})
	t.Run("matching entry is used", func(t *testing.T) {
		identifiers, err := credentialIdentifiersFor(&receiverTypes.CredentialIssuanceAccessToken{
			Token:                "access-1",
			AuthorizationDetails: []receiverTypes.CredentialIssuanceAuthorizationDetail{flowTestOpenIDCredentialDetail("pid", "id-1")},
		}, "pid", authorizationDetailsOptional)
		require.NoError(t, err)
		require.Equal(t, []string{"id-1"}, identifiers)
	})
	t.Run("foreign entry is rejected", func(t *testing.T) {
		_, err := credentialIdentifiersFor(&receiverTypes.CredentialIssuanceAccessToken{
			Token:                "access-1",
			AuthorizationDetails: []receiverTypes.CredentialIssuanceAuthorizationDetail{flowTestOpenIDCredentialDetail("other", "id-other")},
		}, "pid", authorizationDetailsOptional)
		require.ErrorIs(t, err, receiverTypes.ErrInvalidTokenResponse)
		require.ErrorContains(t, err, `authorization_details contains no entry for credential_configuration_id "pid"`)
	})
}

// The mode is wired into the flow: an authorization_details request whose
// Token Response omits authorization_details stops before the Credential
// Endpoint.
func TestIssuanceAuthorizationDetailsModeViolationStops(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	req := fixture.issuanceRequest()
	req.AuthorizationRequestType = AuthorizationRequestDetails
	_, err := fixture.receive(req)
	require.ErrorIs(t, err, ErrAuthorizationDetailsMissing)
	require.Equal(t, 1, fixture.tokenCalls)
	require.Equal(t, 0, fixture.credentialCalls)
}

// ---------------------------------------------------------------------------
// A whole issuance against a strict issuer.
// ---------------------------------------------------------------------------

// flowTestResponseKey reads credential_response_encryption.jwk from a
// decoded (Deferred) Credential Request, recording a failure on obs.
func flowTestResponseKey(obs *serverObservations, body map[string]any) (jose.JSONWebKey, bool) {
	var key jose.JSONWebKey
	encryption, ok := body["credential_response_encryption"].(map[string]any)
	if !assert.True(obs, ok, "request is missing credential_response_encryption: %#v", body) {
		return key, false
	}
	// Section 8.2: jwk and enc, no top-level alg.
	if !assert.NotContains(obs, encryption, "alg") || !assert.Equal(obs, "A128GCM", encryption["enc"]) {
		return key, false
	}
	raw, err := json.Marshal(encryption["jwk"])
	if !assert.NoError(obs, err) || !assert.NoError(obs, key.UnmarshalJSON(raw)) {
		return key, false
	}
	return key, true
}

// An issuer that requires request and response encryption, a client
// attestation with a challenge, DPoP nonces at the token and credential
// endpoints, a deferred issuance and a notification: every stage completes and
// the credential is stored.
func TestIssuanceAgainstAStrictIssuer(t *testing.T) {
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	holderKey := newPrivateJWKForFinalVCITest(t, "holder-key-1")
	clientKey := newPrivateJWKForFinalVCITest(t, "client-key-1")
	attesterKey := newPrivateJWKForFinalVCITest(t, "attester-key-1")
	requestEncryptionKey := newPrivateJWKForFinalVCITest(t, "credential-request-enc-key-1")
	requestEncryptionKey.Algorithm = "ECDH-ES"
	requestEncryptionKey.Use = "enc"
	issuedCredential := buildTestSDJWTVCWithIssuerKey(t, issuerKey, holderKey, map[string]string{"given_name": "Taro"})

	var server *httptest.Server
	obs := newServerObservations(t, "issuer-metadata", "as-metadata", "challenge", "par", "authorize", "token", "nonce", "credential", "deferred", "notification")
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-credential-issuer":
			obs.called("issuer-metadata")
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{
				"credential_issuer":            server.URL,
				"credential_endpoint":          server.URL + "/credential",
				"nonce_endpoint":               server.URL + "/nonce",
				"deferred_credential_endpoint": server.URL + "/deferred",
				"notification_endpoint":        server.URL + "/notification",
				"authorization_servers":        []string{server.URL},
				"credential_response_encryption": map[string]any{
					"alg_values_supported": []string{"ECDH-ES"},
					"enc_values_supported": []string{"A128GCM"},
					"encryption_required":  true,
				},
				"credential_request_encryption": map[string]any{
					"jwks":                 map[string]any{"keys": []any{requestEncryptionKey.Public()}},
					"alg_values_supported": []string{"ECDH-ES"},
					"enc_values_supported": []string{"A128GCM"},
					"encryption_required":  true,
				},
				"credential_configurations_supported": map[string]any{
					"pid": map[string]any{"format": "dc+sd-jwt", "scope": "pid-scope"},
				},
			})
		case "/.well-known/oauth-authorization-server":
			obs.called("as-metadata")
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{
				"issuer":                                server.URL,
				"authorization_endpoint":                server.URL + "/authorize",
				"pushed_authorization_request_endpoint": server.URL + "/par",
				"token_endpoint":                        server.URL + "/token",
				"challenge_endpoint":                    server.URL + "/challenge",
				"pre-authorized_grant_anonymous_access_supported": true,
				"response_types_supported":                        []string{"code"},
			})
		case "/challenge":
			obs.called("challenge")
			mockserver.JSONResponse(w, http.StatusOK, map[string]string{"attestation_challenge": "challenge-1"})
		case "/par":
			obs.called("par")
			if !assert.NotEmpty(obs, r.Header.Get("OAuth-Client-Attestation")) ||
				!assert.NotEmpty(obs, r.Header.Get("OAuth-Client-Attestation-PoP")) ||
				!assert.NoError(obs, r.ParseForm()) {
				http.Error(w, "invalid_client", http.StatusBadRequest)
				return
			}
			for name, want := range map[string]string{
				"response_type":         "code",
				"client_id":             "client-1",
				"redirect_uri":          fixtureRedirectURI,
				"scope":                 "pid-scope",
				"code_challenge_method": "S256",
				"issuer_state":          "issuer-state-1",
			} {
				if !assert.Equal(obs, want, r.Form.Get(name), name) {
					http.Error(w, "invalid_request", http.StatusBadRequest)
					return
				}
			}
			pushedState := r.Form.Get("state")
			if !assert.NotEmpty(obs, pushedState) {
				http.Error(w, "missing state", http.StatusBadRequest)
				return
			}
			obs.set("pushed_state", pushedState)
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{"request_uri": "urn:request:1", "expires_in": 60})
		case "/authorize":
			obs.called("authorize")
			if !assert.Equal(obs, "client-1", r.URL.Query().Get("client_id")) ||
				!assert.Equal(obs, "urn:request:1", r.URL.Query().Get("request_uri")) {
				http.Error(w, "invalid_request_uri", http.StatusBadRequest)
				return
			}
			pushedState, _ := obs.get("pushed_state").(string)
			w.Header().Set("Location", fixtureRedirectURI+"?code=code-1&state="+url.QueryEscape(pushedState))
			w.WriteHeader(http.StatusFound)
		case "/token":
			attempt := obs.called("token")
			if !assert.NotEmpty(obs, r.Header.Get("DPoP")) ||
				!assert.NotEmpty(obs, r.Header.Get("OAuth-Client-Attestation")) ||
				!assert.NoError(obs, r.ParseForm()) ||
				!assert.Equal(obs, "authorization_code", r.Form.Get("grant_type")) ||
				!assert.Equal(obs, "code-1", r.Form.Get("code")) ||
				!assert.Equal(obs, "client-1", r.Form.Get("client_id")) {
				http.Error(w, "invalid_grant", http.StatusBadRequest)
				return
			}
			if attempt == 1 {
				w.Header().Set("DPoP-Nonce", "token-nonce-1")
				mockserver.JSONResponse(w, http.StatusBadRequest, map[string]string{"error": "use_dpop_nonce"})
				return
			}
			mockserver.JSONResponse(w, http.StatusOK, map[string]string{"access_token": "access-1", "token_type": "DPoP"})
		case "/nonce":
			obs.called("nonce")
			mockserver.JSONResponse(w, http.StatusOK, map[string]string{"c_nonce": "credential-nonce-1"})
		case "/credential":
			attempt := obs.called("credential")
			if !assert.Equal(obs, "DPoP access-1", r.Header.Get("Authorization")) || !assert.NotEmpty(obs, r.Header.Get("DPoP")) {
				http.Error(w, "invalid_token", http.StatusUnauthorized)
				return
			}
			if attempt == 1 {
				w.Header().Set("DPoP-Nonce", "credential-nonce-1")
				w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			body, decoded := decodeObservedCredentialRequest(obs, r, requestEncryptionKey)
			if !decoded || !assert.Equal(obs, "pid", body["credential_configuration_id"]) {
				http.Error(w, "invalid_credential_request", http.StatusBadRequest)
				return
			}
			proofs, _ := body["proofs"].(map[string]any)
			if !assert.NotEmpty(obs, proofs["jwt"]) {
				http.Error(w, "invalid_proof", http.StatusBadRequest)
				return
			}
			key, ok := flowTestResponseKey(obs, body)
			if !ok {
				http.Error(w, "invalid_encryption_parameters", http.StatusBadRequest)
				return
			}
			writeObservedFinalCredentialResponse(obs, w, key, map[string]string{"transaction_id": "tx-1"})
		case "/deferred":
			obs.called("deferred")
			if !assert.Equal(obs, "DPoP access-1", r.Header.Get("Authorization")) {
				http.Error(w, "invalid_token", http.StatusUnauthorized)
				return
			}
			body, decoded := decodeObservedCredentialRequest(obs, r, requestEncryptionKey)
			if !decoded || !assert.Equal(obs, "tx-1", body["transaction_id"]) {
				http.Error(w, "invalid_transaction_id", http.StatusBadRequest)
				return
			}
			key, ok := flowTestResponseKey(obs, body)
			if !ok {
				http.Error(w, "invalid_encryption_parameters", http.StatusBadRequest)
				return
			}
			writeObservedFinalCredentialResponse(obs, w, key, map[string]any{
				"credentials":     []any{map[string]any{"credential": issuedCredential}},
				"notification_id": "notification-1",
			})
		case "/notification":
			obs.called("notification")
			var body receiverTypes.NotificationRequest
			if !assert.Equal(obs, "DPoP access-1", r.Header.Get("Authorization")) ||
				!assert.NoError(obs, json.NewDecoder(r.Body).Decode(&body)) ||
				!assert.Equal(obs, "notification-1", body.NotificationID) ||
				!assert.Equal(obs, "credential_accepted", body.Event) {
				http.Error(w, "invalid_notification_request", http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	receiving, err := receiver.NewReceivingDispatcher(receiver.WithPlugin(receiverTypes.Oid4vci, &oid4vci.Oid4vciReceiver{
		HTTPClient: server.Client(),
		AllowHTTP:  true,
	}))
	require.NoError(t, err)
	dpopKey, err := keystore.NewKeyEntryFromJWK(clientKey)
	require.NoError(t, err)
	holderEntry, err := keystore.NewKeyEntryFromJWK(holderKey)
	require.NoError(t, err)
	w, err := NewWalletWithConfig(Config{
		CredStore:            newProfileCredStore(t),
		Receiver:             receiving,
		ClientAuth:           ClientAuthConfig{ClientID: "client-1"},
		Issuance:             IssuanceConfig{RedirectURI: fixtureRedirectURI},
		DPoP:                 DPoPConfig{Key: dpopKey},
		Attestation:          AttestationConfig{Client: &attestation.StaticClientAttester{Key: testKeyEntry(t, attesterKey), Issuer: "https://client-attester.example.org/"}},
		CredentialAcceptance: acceptIssuerKeyPolicy(issuerKey),
	})
	require.NoError(t, err)

	ctx := context.Background()
	issuerURL, err := url.Parse(server.URL)
	require.NoError(t, err)
	authorization, err := w.BeginIssuance(ctx, IssuanceRequest{CredentialOffer: &CredentialOffer{
		CredentialIssuer:           issuerURL,
		CredentialConfigurationIDs: []string{"pid"},
		Grants:                     map[string]*CredentialOfferGrant{"authorization_code": {IssuerState: "issuer-state-1"}},
	}})
	require.NoError(t, err)
	location, err := followAuthorizationRedirect(ctx, server.Client(), authorization.AuthorizationURL)
	require.NoError(t, err)
	grant, err := w.AuthorizeIssuance(ctx, authorization, location)
	require.NoError(t, err)
	result, err := w.RequestCredential(ctx, grant, CredentialRequest{HolderKeys: []IKeyEntry{holderEntry}})
	require.NoError(t, err)
	require.NotNil(t, result.Deferred)
	require.Empty(t, result.Credentials)

	result, err = w.RequestDeferredCredential(ctx, result.Deferred)
	require.NoError(t, err)
	require.Nil(t, result.Deferred)
	require.NotNil(t, result.CredentialResponse)
	require.Equal(t, []any{map[string]any{"credential": issuedCredential}}, result.CredentialResponse.Credentials)
	require.Len(t, result.Credentials, 1)
	require.Equal(t, []byte(issuedCredential), result.Credentials[0].Entry.Raw)
	require.Equal(t, string(credential.SDJwtVC), result.Credentials[0].Entry.MimeType)
	entries, _, err := w.GetCredentialEntries(GetCredentialEntriesRequest{})
	require.NoError(t, err)
	require.Len(t, entries, 1)

	require.NotNil(t, result.Notification)
	require.NoError(t, w.NotifyIssuer(ctx, result.Notification, NotificationCredentialAccepted, ""))
	require.Equal(t, 2, obs.callCount("token"))
	require.Equal(t, 2, obs.callCount("credential"))
	require.Equal(t, 1, obs.callCount("deferred"))
	require.Equal(t, 1, obs.callCount("notification"))
}

// HAIP Section 4.4.1 requires client authentication at the endpoints that
// support it (PAR and token). The Credential and Deferred Credential Requests
// authenticate with the access token alone, so a wallet without a client
// authentication mechanism still sends them.
func TestIssuanceHAIPCredentialStagesNeedNoClientAuthentication(t *testing.T) {
	fixture := newHAIPIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.includeDeferredEndpoint = true
		f.credentialHandler = func(w http.ResponseWriter, _ *http.Request) {
			mockserver.JSONResponse(w, http.StatusAccepted, map[string]any{"transaction_id": "tx-1"})
		}
		f.deferredHandler = func(w http.ResponseWriter, _ *http.Request) {
			mockserver.JSONResponse(w, http.StatusBadRequest, map[string]any{"error": "issuance_pending"})
		}
	})
	ctx := context.Background()
	authorization := flowTestBegin(t, fixture)
	location, err := fixture.followAuthorization(authorization)
	require.NoError(t, err)
	grant, err := fixture.wallet.AuthorizeIssuance(ctx, authorization, location)
	require.NoError(t, err)

	fixture.clientAuthKey = nil
	poller := fixture.newWallet(t)

	result, err := poller.RequestCredential(ctx, grant, fixture.credentialRequest())
	require.NoError(t, err)
	require.NotNil(t, result.Deferred)
	require.Equal(t, 1, fixture.credentialCalls)

	pending, err := poller.RequestDeferredCredential(ctx, result.Deferred)
	require.NoError(t, err)
	require.NotNil(t, pending.Deferred)
	require.Equal(t, 1, fixture.deferredCalls)

	// The token endpoint still requires it.
	_, err = poller.AuthorizeIssuance(ctx, authorization, location)
	require.ErrorIs(t, err, ErrInvalidArgument)
	require.ErrorContains(t, err, "HAIP requires an OAuth2 client authentication mechanism")
}
