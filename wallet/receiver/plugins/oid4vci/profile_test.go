package oid4vci

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
	"github.com/trustknots/vcknots/wallet/profile"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

// newTokenServer returns an endpoint whose token response carries tokenType.
func newTokenServer(t *testing.T, tokenType string) common.URIField {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mockserver.JSONResponse(w, http.StatusOK, map[string]string{
			"access_token": "access-token",
			"token_type":   tokenType,
		})
	}))
	t.Cleanup(server.Close)
	parsed, err := url.Parse(server.URL + "/token")
	require.NoError(t, err)
	return common.URIField(*parsed)
}

// TestOid4vciReceiver_ProfileTokenType checks HAIP §4 "Sender-constrained
// access token: MUST support DPoP" in both directions.
func TestOid4vciReceiver_ProfileTokenType(t *testing.T) {
	t.Run("pre-authorized token path", func(t *testing.T) {
		bearer := newTokenServer(t, "Bearer")
		final := &Oid4vciReceiver{AllowHTTP: true, Profile: profile.Final}
		token, err := final.FetchAccessToken(types.Oid4vci, bearer, "code", "")
		require.NoError(t, err)
		require.Equal(t, "Bearer", token.TokenType)

		haip := &Oid4vciReceiver{AllowHTTP: true, Profile: profile.HAIP}
		_, err = haip.FetchAccessToken(types.Oid4vci, bearer, "code", "")
		require.ErrorContains(t, err, "HAIP requires a DPoP-bound access token")
	})

	t.Run("DPoP token type is case-insensitive", func(t *testing.T) {
		dpop := newTokenServer(t, "dpop")
		haip := &Oid4vciReceiver{AllowHTTP: true, Profile: profile.HAIP}
		token, err := haip.FetchAccessToken(types.Oid4vci, dpop, "code", "")
		require.NoError(t, err)
		require.Equal(t, "dpop", token.TokenType)
	})

	t.Run("authorization code exchange", func(t *testing.T) {
		bearer := newTokenServer(t, "Bearer")
		request := types.TokenRequest{
			GrantType: types.AuthorizationCode, Code: "code", RedirectURI: "https://wallet.example/cb", CodeVerifier: "verifier", ClientID: "client",
		}
		final := &Oid4vciReceiver{AllowHTTP: true, Profile: profile.Final}
		_, err := final.RequestToken(t.Context(), bearer, request, types.ClientAuthentication{DPoP: fixedProof("proof")})
		require.NoError(t, err)

		haip := &Oid4vciReceiver{AllowHTTP: true, Profile: profile.HAIP}
		_, err = haip.RequestToken(t.Context(), bearer, request, types.ClientAuthentication{DPoP: fixedProof("proof")})
		require.ErrorContains(t, err, "HAIP requires a DPoP-bound access token")
	})

	t.Run("authorization code DPoP retry exchange", func(t *testing.T) {
		bearer := newTokenServer(t, "Bearer")
		request := types.TokenRequest{
			GrantType: types.AuthorizationCode, Code: "code", RedirectURI: "https://wallet.example/cb", CodeVerifier: "verifier", ClientID: "client",
		}
		haip := &Oid4vciReceiver{AllowHTTP: true, Profile: profile.HAIP}
		_, err := haip.RequestToken(t.Context(), bearer, request, types.ClientAuthentication{ClientAttestation: func() (types.OAuthClientAttestationHeaders, error) {
			return types.OAuthClientAttestationHeaders{}, nil
		}, DPoP: func(string) (string, error) { return "proof", nil }})
		require.ErrorContains(t, err, "HAIP requires a DPoP-bound access token")
	})

	t.Run("unknown profile fails closed", func(t *testing.T) {
		bearer := newTokenServer(t, "DPoP")
		receiver := &Oid4vciReceiver{AllowHTTP: true, Profile: profile.Profile("bogus")}
		_, err := receiver.FetchAccessToken(types.Oid4vci, bearer, "code", "")
		require.ErrorContains(t, err, "unknown protocol profile")
	})
}

// TestOid4vciReceiver_ProfileCredentialConfiguration covers HAIP §4.1 (scope)
// and §5.3.2/§6 (formats).
func TestOid4vciReceiver_ProfileCredentialConfiguration(t *testing.T) {
	haip := &Oid4vciReceiver{Profile: profile.HAIP}
	final := &Oid4vciReceiver{Profile: profile.Final}

	t.Run("Final accepts everything", func(t *testing.T) {
		for _, config := range []types.CredentialConfiguration{
			{},
			{Format: "vc+sd-jwt"},
			{Format: "jwt_vc_json"},
			{Format: "dc+sd-jwt"},
		} {
			require.NoError(t, final.ValidateCredentialConfigurationForProfile(config))
		}
	})

	t.Run("HAIP accepts scoped dc+sd-jwt and mso_mdoc", func(t *testing.T) {
		require.NoError(t, haip.ValidateCredentialConfigurationForProfile(types.CredentialConfiguration{Format: "dc+sd-jwt", Scope: "pid"}))
		require.NoError(t, haip.ValidateCredentialConfigurationForProfile(types.CredentialConfiguration{Format: "mso_mdoc", Scope: "mdl"}))
	})

	t.Run("HAIP rejects a missing scope", func(t *testing.T) {
		require.ErrorContains(t, haip.ValidateCredentialConfigurationForProfile(types.CredentialConfiguration{Format: "dc+sd-jwt"}), "requires a scope")
	})

	t.Run("HAIP rejects other formats", func(t *testing.T) {
		for _, format := range []string{"vc+sd-jwt", "jwt_vc_json", "ldp_vc"} {
			err := haip.ValidateCredentialConfigurationForProfile(types.CredentialConfiguration{Format: format, Scope: "scope"})
			require.ErrorContains(t, err, "dc+sd-jwt or mso_mdoc")
		}
	})
}

// TestDiscoverCredentialIssuerAppliesHAIPNonceEndpointRule covers HAIP
// Section 4.1: issuer metadata that advertises
// cryptographic_binding_methods_supported must name a nonce_endpoint.
func TestDiscoverCredentialIssuerAppliesHAIPNonceEndpointRule(t *testing.T) {
	bindingMethods := []string{"jwk", "cose_key"}
	withBinding := types.CredentialConfiguration{
		Format:                               "dc+sd-jwt",
		Scope:                                "pid",
		CryptographicBindingMethodsSupported: &bindingMethods,
	}
	withoutBinding := types.CredentialConfiguration{Format: "dc+sd-jwt", Scope: "pid"}

	discover := func(t *testing.T, p profile.Profile, config types.CredentialConfiguration, withNonceEndpoint bool) error {
		t.Helper()
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			base := "https://" + r.Host
			metadata := map[string]any{
				"credential_issuer":                   base,
				"credential_endpoint":                 base + "/credential",
				"credential_configurations_supported": map[string]any{"pid": config},
			}
			if withNonceEndpoint {
				metadata["nonce_endpoint"] = base + "/nonce"
			}
			mockserver.JSONResponse(w, http.StatusOK, metadata)
		}))
		t.Cleanup(server.Close)
		receiver := &Oid4vciReceiver{HTTPClient: server.Client(), Profile: p}
		_, err := receiver.DiscoverCredentialIssuer(t.Context(), common.URIField(*mustParseURL(t, server.URL)))
		return err
	}

	t.Run("Final accepts metadata without nonce_endpoint", func(t *testing.T) {
		require.NoError(t, discover(t, profile.Final, withBinding, false))
	})
	t.Run("HAIP rejects a binding method without nonce_endpoint", func(t *testing.T) {
		require.ErrorContains(t, discover(t, profile.HAIP, withBinding, false), "requires nonce_endpoint")
	})
	t.Run("HAIP accepts once nonce_endpoint is present", func(t *testing.T) {
		require.NoError(t, discover(t, profile.HAIP, withBinding, true))
	})
	t.Run("HAIP accepts configurations without binding methods", func(t *testing.T) {
		require.NoError(t, discover(t, profile.HAIP, withoutBinding, false))
	})
}

// TestOid4vciReceiver_ProfileAllowHTTP covers the HAIP transport policy.
func TestOid4vciReceiver_ProfileAllowHTTP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "http://" + r.Host
		mockserver.JSONResponse(w, http.StatusOK, map[string]any{
			"credential_issuer":   base,
			"credential_endpoint": base + "/credential",
		})
	}))
	t.Cleanup(server.Close)
	endpoint := common.URIField(*mustParseURL(t, server.URL))

	haip := &Oid4vciReceiver{AllowHTTP: true, Profile: profile.HAIP}
	_, err := haip.FetchIssuerMetadata(endpoint, types.Oid4vci)
	require.ErrorContains(t, err, "HAIP profile does not permit AllowHTTP")
	code, coded := common.CodeOf(err)
	require.True(t, coded)
	require.Equal(t, "invalid_argument", code)

	final := &Oid4vciReceiver{AllowHTTP: true, Profile: profile.Final}
	_, err = final.FetchIssuerMetadata(endpoint, types.Oid4vci)
	require.NoError(t, err)
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	require.NoError(t, err)
	return parsed
}
