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
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/env"
	"github.com/trustknots/vcknots/wallet/internal/httpfetch"
	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
	"github.com/trustknots/vcknots/wallet/receiver"
	"github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// authorizeTestOfferWallet is a wallet whose OID4VCI receiver talks to server
// with the given plain-HTTP allowance.
func authorizeTestOfferWallet(t *testing.T, server *httptest.Server, allowHTTP bool) *Wallet {
	t.Helper()
	plugin := &oid4vci.Oid4vciReceiver{HTTPClient: server.Client(), AllowHTTP: allowHTTP}
	receiving, err := receiver.NewReceivingDispatcher(receiver.WithPlugin(receiverTypes.Oid4vci, plugin))
	require.NoError(t, err)
	w, err := NewWalletWithConfig(Config{CredStore: newProfileCredStore(t), Receiver: receiving})
	require.NoError(t, err)
	return w
}

// authorizeTestDecodeDetails decodes an authorization_details form value.
func authorizeTestDecodeDetails(t *testing.T, raw string) []map[string]any {
	t.Helper()
	require.NotEmpty(t, raw)
	var details []map[string]any
	require.NoError(t, json.Unmarshal([]byte(raw), &details))
	return details
}

// authorizeTestDetailsTokenResponse is a Section 6.2 Token Response with one
// openid_credential entry for credentialConfigurationID.
func authorizeTestDetailsTokenResponse(credentialConfigurationID, identifier string) map[string]any {
	return map[string]any{
		"access_token": "access-1",
		"token_type":   "DPoP",
		"expires_in":   3600,
		"authorization_details": []map[string]any{
			{
				"type":                        receiverTypes.AuthorizationDetailTypeOpenIDCredential,
				"credential_configuration_id": credentialConfigurationID,
				"credential_identifiers":      []string{identifier},
			},
		},
	}
}

// authorizeTestRequireCoded fails unless err carries an error code.
func authorizeTestRequireCoded(t *testing.T, err error) {
	t.Helper()
	code, ok := ErrorCode(err)
	require.True(t, ok, "error has no code: %v", err)
	require.NotEqual(t, "unclassified", code, "error is unclassified: %v", err)
}

func TestResolveCredentialOffer_ByReference(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)

	offerURI := "openid-credential-offer://?credential_offer_uri=" + url.QueryEscape(fixture.server.URL+"/offer")
	offer, err := fixture.wallet.ResolveCredentialOffer(context.Background(), offerURI)
	require.NoError(t, err)
	require.Equal(t, fixture.server.URL, offer.CredentialIssuer.String())
	require.Equal(t, []string{"pid"}, offer.CredentialConfigurationIDs)
	require.Equal(t, "issuer-state-1", offer.Grants["authorization_code"].IssuerState)
}

func TestResolveCredentialOffer_RejectsBothParameters(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	offerURI := "openid-credential-offer://?credential_offer=" +
		url.QueryEscape(`{"credential_issuer":"`+fixture.server.URL+`","credential_configuration_ids":["pid"]}`) +
		"&credential_offer_uri=" + url.QueryEscape(fixture.server.URL+"/offer")
	_, err := fixture.wallet.ResolveCredentialOffer(context.Background(), offerURI)
	require.ErrorIs(t, err, ErrInvalidArgument)
	require.ErrorContains(t, err, "both")
}

func TestResolveCredentialOffer_ByReferenceEnforcesSizeLimit(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	offerURI := "openid-credential-offer://?credential_offer_uri=" + url.QueryEscape(fixture.server.URL+"/bigoffer")
	_, err := fixture.wallet.ResolveCredentialOffer(context.Background(), offerURI)
	require.ErrorIs(t, err, httpfetch.ErrBodyTooLarge)
	authorizeTestRequireCoded(t, err)
}

// The plain-HTTP escape is the receiver's AllowHTTP alone: the process-wide
// environment switch does not widen it for offer resolution.
func TestResolveCredentialOffer_PlainHTTPFollowsReceiverPolicyOnly(t *testing.T) {
	t.Setenv(env.HTTP_ALLOWED.String(), "true")
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		mockserver.JSONResponse(w, http.StatusOK, map[string]any{"credential_issuer": "https://issuer.example"})
	}))
	defer server.Close()

	w := authorizeTestOfferWallet(t, server, false)
	_, err := w.ResolveCredentialOffer(context.Background(), "openid-credential-offer://?credential_offer_uri="+url.QueryEscape(server.URL+"/offer"))
	require.ErrorContains(t, err, "https")
	require.Equal(t, 0, calls)
}

// A credential_offer_uri that redirects is refused rather than followed, and
// Section 4.1.3 requires the offer to be served as application/json.
func TestResolveCredentialOffer_RefusesRedirectAndWrongMediaType(t *testing.T) {
	offerCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "/offer", http.StatusFound)
		case "/text":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(`{"credential_issuer":"https://issuer.example"}`))
		default:
			offerCalls++
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{"credential_issuer": "https://issuer.example"})
		}
	}))
	defer server.Close()
	w := authorizeTestOfferWallet(t, server, true)

	_, err := w.ResolveCredentialOffer(context.Background(), "openid-credential-offer://?credential_offer_uri="+url.QueryEscape(server.URL+"/redirect"))
	require.ErrorIs(t, err, ErrHTTPRedirectNotAllowed)
	require.ErrorContains(t, err, "302")
	require.Equal(t, 0, offerCalls)

	_, err = w.ResolveCredentialOffer(context.Background(), "openid-credential-offer://?credential_offer_uri="+url.QueryEscape(server.URL+"/text"))
	require.ErrorContains(t, err, "application/json")
}

// A credential_offer_uri served with another media type is refused with a
// coded error, like every other refusal of ResolveCredentialOffer.
func TestResolveCredentialOffer_WrongMediaTypeErrorIsCoded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(`{"credential_issuer":"https://issuer.example"}`))
	}))
	defer server.Close()
	w := authorizeTestOfferWallet(t, server, true)
	_, err := w.ResolveCredentialOffer(context.Background(), "openid-credential-offer://?credential_offer_uri="+url.QueryEscape(server.URL+"/text"))
	require.ErrorContains(t, err, "application/json")
	authorizeTestRequireCoded(t, err)
}

func TestBeginIssuance_IssuerIdentifierMismatch(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.credentialIssuerOverride = "https://other.example"
	})
	_, err := fixture.wallet.BeginIssuance(context.Background(), fixture.issuanceRequest())
	require.ErrorIs(t, err, ErrIssuerIdentifierMismatch)
	require.Equal(t, 0, fixture.asMetadataCalls)
	require.Equal(t, 0, fixture.parCalls)
	require.Equal(t, 0, fixture.credentialCalls)
}

// OpenID4VCI 1.0 Section 12.2.2 identifies the Credential Issuer by an https
// URL. A wallet whose receiver does not allow plain HTTP refuses a plain-http
// issuer at metadata discovery, before any authorization request.
func TestBeginIssuance_RefusesPlainHTTPIssuerWithoutAllowance(t *testing.T) {
	t.Setenv(env.HTTP_ALLOWED.String(), "")

	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		mockserver.JSONResponse(w, http.StatusOK, map[string]any{})
	}))
	defer server.Close()
	issuerURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	plugin := receiverTypes.Receiver(&oid4vci.Oid4vciReceiver{HTTPClient: server.Client(), AllowHTTP: false})
	receiving, err := receiver.NewReceivingDispatcher(receiver.WithPlugin(receiverTypes.Oid4vci, plugin))
	require.NoError(t, err)
	wallet, err := NewWalletWithConfig(Config{
		CredStore:            newProfileCredStore(t),
		Receiver:             receiving,
		CredentialAcceptance: acceptIssuerKeyPolicy(issuerKey),
		ClientAuth:           ClientAuthConfig{ClientID: "client-1"},
		Issuance:             IssuanceConfig{RedirectURI: fixtureRedirectURI},
	})
	require.NoError(t, err)

	_, err = wallet.BeginIssuance(context.Background(), IssuanceRequest{CredentialOffer: &CredentialOffer{
		CredentialIssuer:           issuerURL,
		CredentialConfigurationIDs: []string{"pid"},
		Grants: map[string]*CredentialOfferGrant{
			"authorization_code": {IssuerState: "issuer-state-1"},
		},
	}})
	require.ErrorContains(t, err, "https required")
	require.Equal(t, 0, calls)
}

func TestBeginIssuance_AuthorizationServerHintNotListed(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	req := fixture.issuanceRequest()
	req.CredentialOffer.Grants["authorization_code"].AuthorizationServer = "https://evil.example"
	_, err := fixture.wallet.BeginIssuance(context.Background(), req)
	require.ErrorIs(t, err, receiverTypes.ErrInvalidMetadata)
	require.ErrorContains(t, err, "not listed")
	require.Equal(t, 0, fixture.asMetadataCalls)
	require.Equal(t, 0, fixture.parCalls)
}

func TestBeginIssuance_AuthorizationServerMetadataIssuerMismatch(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.asIssuerOverride = "https://other.example"
	})
	_, err := fixture.wallet.BeginIssuance(context.Background(), fixture.issuanceRequest())
	require.ErrorIs(t, err, oid4vci.ErrAuthorizationServerIssuerMismatch)
	require.Equal(t, 0, fixture.parCalls)
}

func TestAuthorizeIssuance_RedirectOriginMismatch(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.authorizeLocation = func(f *finalIssuanceFixture, state string) string {
			return "https://attacker.example/callback?code=code-1&state=" + url.QueryEscape(state)
		}
	})
	_, err := fixture.authorize(fixture.issuanceRequest())
	require.ErrorIs(t, err, ErrAuthorizationRedirectURIMismatch)
	require.Equal(t, 1, fixture.authorizeCalls)
	require.Equal(t, 0, fixture.tokenCalls)
}

func TestAuthorizeIssuance_ErrorRedirectSurfaced(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.authorizeLocation = func(f *finalIssuanceFixture, state string) string {
			return fixtureRedirectURI + "?error=access_denied&error_description=denied&state=" + url.QueryEscape(state)
		}
	})
	_, err := fixture.authorize(fixture.issuanceRequest())
	var responseErr *AuthorizationResponseError
	require.True(t, errors.As(err, &responseErr), "err = %v", err)
	require.Equal(t, "access_denied", responseErr.Code)
	require.Equal(t, "denied", responseErr.Description)
	require.Equal(t, fixture.pushedState, responseErr.State)
	require.Equal(t, 0, fixture.tokenCalls)
}

// RFC 9126 Section 2.2: the pushed request_uri expires after expires_in, and
// the authorization state reports when it can no longer be opened.
func TestBeginIssuance_ReportsRequestURIExpiry(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	before := time.Now()
	authorization, err := fixture.wallet.BeginIssuance(context.Background(), fixture.issuanceRequest())
	require.NoError(t, err)
	require.False(t, authorization.RequestURIExpiresAt.IsZero())
	require.WithinDuration(t, before.Add(60*time.Second), authorization.RequestURIExpiresAt, 5*time.Second)
	require.False(t, authorization.RequestURIExpired(time.Now()))
	require.True(t, authorization.RequestURIExpired(authorization.RequestURIExpiresAt))
	require.True(t, authorization.RequestURIExpired(time.Now().Add(61*time.Second)))
}

// OpenID4VCI 1.0 Section 6.2: each authorization_details entry names its
// Credential Configuration and carries the credential_identifiers for it, so
// the wallet takes the identifier from the entry that matches its request.
func TestAuthorizeIssuance_CredentialIdentifierUsesMatchingConfigurationEntry(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.tokenResponse = map[string]any{
			"access_token": "access-1",
			"token_type":   "DPoP",
			"authorization_details": []map[string]any{
				{
					"type":                        receiverTypes.AuthorizationDetailTypeOpenIDCredential,
					"credential_configuration_id": "other",
					"credential_identifiers":      []string{"id-other"},
				},
				{
					"type":                        receiverTypes.AuthorizationDetailTypeOpenIDCredential,
					"credential_configuration_id": "pid",
					"credential_identifiers":      []string{"id-1"},
				},
			},
		}
	})
	grant, err := fixture.authorize(fixture.issuanceRequest())
	require.NoError(t, err)
	require.Equal(t, []string{"id-1"}, grant.CredentialIdentifiers)

	_, err = fixture.wallet.RequestCredential(context.Background(), grant, fixture.credentialRequest())
	require.NoError(t, err)
	require.Equal(t, "id-1", fixture.lastCredentialBody["credential_identifier"])
	_, hasConfigurationID := fixture.lastCredentialBody["credential_configuration_id"]
	require.False(t, hasConfigurationID)
}

// An identifier of another Credential Configuration is not a substitute:
// Section 6.2 scopes credential_identifiers to their own entry.
func TestAuthorizeIssuance_CredentialIdentifierRejectsForeignConfigurationEntry(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.tokenResponse = map[string]any{
			"access_token": "access-1",
			"token_type":   "DPoP",
			"authorization_details": []map[string]any{
				{
					"type":                        receiverTypes.AuthorizationDetailTypeOpenIDCredential,
					"credential_configuration_id": "other",
					"credential_identifiers":      []string{"id-other"},
				},
			},
		}
	})
	_, err := fixture.authorize(fixture.issuanceRequest())
	require.ErrorIs(t, err, receiverTypes.ErrInvalidTokenResponse)
	require.ErrorContains(t, err, `authorization_details contains no entry for credential_configuration_id "pid"`)
	require.Equal(t, 1, fixture.tokenCalls)
	require.Equal(t, 0, fixture.credentialCalls)
}

// Section 8.2: without authorization_details the Credential Request names the
// Credential Configuration instead of an identifier.
func TestAuthorizeIssuance_NoAuthorizationDetailsNamesConfiguration(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	grant, err := fixture.authorize(fixture.issuanceRequest())
	require.NoError(t, err)
	require.Empty(t, grant.CredentialIdentifiers)

	_, err = fixture.wallet.RequestCredential(context.Background(), grant, fixture.credentialRequest())
	require.NoError(t, err)
	require.Equal(t, "pid", fixture.lastCredentialBody["credential_configuration_id"])
	_, hasIdentifier := fixture.lastCredentialBody["credential_identifier"]
	require.False(t, hasIdentifier)
}

// OpenID4VCI 1.0 Sections 5.1.2 and 12.2.4: the default requests the scope
// the Credential Configuration advertises.
func TestBeginIssuance_DefaultUsesScopeWhenAdvertised(t *testing.T) {
	fixture := newFinalIssuanceFixture(t)
	authorization, err := fixture.wallet.BeginIssuance(context.Background(), fixture.issuanceRequest())
	require.NoError(t, err)
	require.Equal(t, "pid-scope", fixture.parForm.Get("scope"))
	require.Empty(t, fixture.parForm.Get("authorization_details"))
	require.False(t, authorization.AuthorizationDetailsRequested)
}

// OpenID4VCI 1.0 Section 12.2.4: "If scope is absent, the only way to request
// the Credential is using authorization_details".
func TestBeginIssuance_DefaultUsesAuthorizationDetailsWithoutScope(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.omitScope = true
		f.tokenResponse = authorizeTestDetailsTokenResponse("pid", "id-1")
	})
	_, err := fixture.receive(fixture.issuanceRequest())
	require.NoError(t, err)
	require.Empty(t, fixture.parForm.Get("scope"))
	details := authorizeTestDecodeDetails(t, fixture.parForm.Get("authorization_details"))
	require.Len(t, details, 1)
	require.Equal(t, receiverTypes.AuthorizationDetailTypeOpenIDCredential, details[0]["type"])
	require.Equal(t, "pid", details[0]["credential_configuration_id"])
}

// OpenID4VCI 1.0 Section 5.1.1: explicit authorization_details sends an
// openid_credential entry with credential_configuration_id and no scope.
func TestBeginIssuance_ExplicitAuthorizationDetails(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.tokenResponse = authorizeTestDetailsTokenResponse("pid", "id-1")
	})
	req := fixture.issuanceRequest()
	req.AuthorizationRequestType = AuthorizationRequestDetails
	authorization, err := fixture.wallet.BeginIssuance(context.Background(), req)
	require.NoError(t, err)
	require.True(t, authorization.AuthorizationDetailsRequested)
	require.Empty(t, fixture.parForm.Get("scope"))
	details := authorizeTestDecodeDetails(t, fixture.parForm.Get("authorization_details"))
	require.Len(t, details, 1)
	require.Equal(t, receiverTypes.AuthorizationDetailTypeOpenIDCredential, details[0]["type"])
	require.Equal(t, "pid", details[0]["credential_configuration_id"])
}

// OpenID4VCI 1.0 Section 5.1.2: explicit scope requires an advertised scope;
// the failure happens before PAR.
func TestBeginIssuance_ExplicitScopeWithoutAdvertisedScopeFailsBeforePAR(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.omitScope = true
	})
	req := fixture.issuanceRequest()
	req.AuthorizationRequestType = AuthorizationRequestScope
	_, err := fixture.wallet.BeginIssuance(context.Background(), req)
	require.ErrorIs(t, err, receiverTypes.ErrInvalidMetadata)
	require.ErrorContains(t, err, "scope")
	require.Equal(t, 0, fixture.parCalls)
}

// OpenID4VCI 1.0 Section 6.2: with authorization_details requested, the
// wallet uses the first credential_identifier of the entry for the requested
// configuration.
func TestAuthorizeIssuance_RARPathMapsCredentialIdentifierByConfiguration(t *testing.T) {
	fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
		f.tokenResponse = map[string]any{
			"access_token": "access-1",
			"token_type":   "DPoP",
			"authorization_details": []map[string]any{
				{
					"type":                        receiverTypes.AuthorizationDetailTypeOpenIDCredential,
					"credential_configuration_id": "pid",
					"credential_identifiers":      []string{"id-1"},
				},
			},
		}
	})
	req := fixture.issuanceRequest()
	req.AuthorizationRequestType = AuthorizationRequestDetails
	_, err := fixture.receive(req)
	require.NoError(t, err)
	require.Equal(t, "id-1", fixture.lastCredentialBody["credential_identifier"])
	_, hasConfigurationID := fixture.lastCredentialBody["credential_configuration_id"]
	require.False(t, hasConfigurationID)
}

// RFC 9207 Section 2.4: a present iss must identify the authorization server;
// when the server advertises support, the parameter is required.
func TestValidateAuthorizationRedirect_ValidatesIssuer(t *testing.T) {
	const authorizationURL = "https://as.example/authorize?client_id=client-1&request_uri=urn%3Arequest%3A1"
	const registered = "https://wallet.example/callback"
	validate := func(location string, policy authorizationResponseIssuerPolicy) (string, error) {
		return validateAuthorizationRedirect(location, authorizationURL, "state-1", registered, policy)
	}

	code, err := validate(registered+"?code=c1&state=state-1&iss=https%3A%2F%2Fas.example",
		authorizationResponseIssuerPolicy{expected: "https://as.example", required: true})
	require.NoError(t, err)
	require.Equal(t, "c1", code)

	_, err = validate(registered+"?code=c1&state=state-1&iss=https%3A%2F%2Fattacker.example",
		authorizationResponseIssuerPolicy{expected: "https://as.example"})
	require.ErrorIs(t, err, ErrAuthorizationIssMismatch)

	missing := registered + "?code=c1&state=state-1"
	_, err = validate(missing, authorizationResponseIssuerPolicy{expected: "https://as.example", required: true})
	require.ErrorIs(t, err, ErrAuthorizationIssMissing)
	code, err = validate(missing, authorizationResponseIssuerPolicy{expected: "https://as.example"})
	require.NoError(t, err)
	require.Equal(t, "c1", code)
}

// The fixture authorization server advertises the RFC 9207 iss parameter; a
// redirect that omits it or names another issuer is refused before the token
// request.
func TestAuthorizeIssuance_AdvertisedIssParameterIsEnforced(t *testing.T) {
	for name, tc := range map[string]struct {
		iss  func(f *finalIssuanceFixture) string
		want error
	}{
		"missing":  {iss: func(*finalIssuanceFixture) string { return "" }, want: ErrAuthorizationIssMissing},
		"mismatch": {iss: func(*finalIssuanceFixture) string { return "https://attacker.example" }, want: ErrAuthorizationIssMismatch},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newFinalIssuanceFixture(t, func(f *finalIssuanceFixture) {
				f.issParameterSupported = true
				f.authorizeLocation = func(f *finalIssuanceFixture, state string) string {
					location := fixtureRedirectURI + "?code=code-1&state=" + url.QueryEscape(state)
					if iss := tc.iss(f); iss != "" {
						location += "&iss=" + url.QueryEscape(iss)
					}
					return location
				}
			})
			_, err := fixture.authorize(fixture.issuanceRequest())
			require.ErrorIs(t, err, tc.want)
			require.Equal(t, 0, fixture.tokenCalls)
		})
	}
}
