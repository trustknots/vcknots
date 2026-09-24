package mockserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateClientAssertionTimeClaims(t *testing.T) {
	const (
		clientID = "wallet-id"
		audience = "https://authorization-server.example.com"
	)

	keyPair := MustGenerateKeyPair("client-key")
	builder := MustNewJWTBuilder(keyPair)
	publicKey := keyPair.CreatePublicJWK()
	server := &OID4VCIIssuerServer{
		config: &OID4VCIIssuerConfig{
			ClientAuthPublicKey:     &publicKey,
			ExpectedClientID:        clientID,
			ClientAssertionAudience: audience,
		},
	}

	tests := []struct {
		name       string
		expiration int64
		notBefore  int64
		wantErr    string
	}{
		{
			name:       "valid",
			expiration: time.Now().Add(time.Minute).Unix(),
			notBefore:  time.Now().Add(-time.Minute).Unix(),
		},
		{
			name:       "expired",
			expiration: time.Now().Add(-time.Minute).Unix(),
			wantErr:    "client_assertion has expired",
		},
		{
			name:       "expires now",
			expiration: time.Now().Unix(),
			wantErr:    "client_assertion has expired",
		},
		{
			name:       "missing",
			expiration: 0,
			wantErr:    "client_assertion exp is required",
		},
		{
			name:       "not valid yet",
			expiration: time.Now().Add(time.Minute).Unix(),
			notBefore:  time.Now().Add(time.Minute).Unix(),
			wantErr:    "client_assertion is not yet valid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertion, err := builder.CreateSignedJWT(clientID, map[string]interface{}{
				"sub": clientID,
				"aud": audience,
				"exp": tt.expiration,
				"nbf": tt.notBefore,
			})
			require.NoError(t, err)

			form := url.Values{
				"client_id":             {clientID},
				"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
				"client_assertion":      {assertion},
			}
			req, err := http.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			err = server.validateClientAssertion(req)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

// mockIssuerTestSigner builds the compact JWSs a wallet sends to this issuer:
// a DPoP proof and a §8.2.1.1 key proof, both with the public key in the jwk
// protected header, which is how the wallet's own signer builds them.
type mockIssuerTestSigner struct {
	key jose.JSONWebKey
}

func newMockIssuerTestSigner(t *testing.T) mockIssuerTestSigner {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return mockIssuerTestSigner{key: jose.JSONWebKey{Key: private, Algorithm: string(jose.ES256)}}
}

func (s mockIssuerTestSigner) sign(t *testing.T, typ string, claims map[string]any) string {
	t.Helper()
	public := s.key.Public()
	options := (&jose.SignerOptions{}).WithType(jose.ContentType(typ))
	options.EmbedJWK = true
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: s.key.Key}, options)
	require.NoError(t, err)
	_ = public
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)
	return token
}

func (s mockIssuerTestSigner) dpopProof(t *testing.T, method, endpoint, accessToken, nonce string) string {
	t.Helper()
	claims := map[string]any{
		"htm": method,
		"htu": endpoint,
		"iat": time.Now().Unix(),
		"jti": "jti-1",
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if accessToken != "" {
		digest := sha256.Sum256([]byte(accessToken))
		claims["ath"] = base64.RawURLEncoding.EncodeToString(digest[:])
	}
	return s.sign(t, "dpop+jwt", claims)
}

func (s mockIssuerTestSigner) keyProof(t *testing.T, audience, nonce string) string {
	t.Helper()
	claims := map[string]any{"aud": audience, "iat": time.Now().Unix()}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	return s.sign(t, "openid4vci-proof+jwt", claims)
}

func postForm(t *testing.T, url string, form url.Values, headers map[string]string) (int, map[string]any) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, url, strings.NewReader(form.Encode()))
	require.NoError(t, err)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	defer response.Body.Close()
	body := map[string]any{}
	_ = json.NewDecoder(response.Body).Decode(&body)
	return response.StatusCode, body
}

func postJSON(t *testing.T, url string, payload string, headers map[string]string) (int, map[string]any) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, url, strings.NewReader(payload))
	require.NoError(t, err)
	request.Header.Set("Content-Type", "application/json")
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	defer response.Body.Close()
	body := map[string]any{}
	_ = json.NewDecoder(response.Body).Decode(&body)
	return response.StatusCode, body
}

// TestTokenEndpointRejectsWhatARealIssuerRejects covers the grant rules the
// mock enforces: RFC 6749 §5.2 unsupported_grant_type, the per-grant required
// parameter and the RFC 7636 §4.6 PKCE comparison.
func TestTokenEndpointRejectsWhatARealIssuerRejects(t *testing.T) {
	verifier := strings.Repeat("a", 43)
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])

	config := DefaultOID4VCIIssuerConfig()
	config.PKCECodeChallenge = challenge
	issuer := NewOID4VCIIssuerServer(config)
	defer issuer.Close()
	tokenEndpoint := issuer.URL() + "/token"

	t.Run("the configured grant with a matching verifier is accepted", func(t *testing.T) {
		status, body := postForm(t, tokenEndpoint, url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {"code-1"},
			"code_verifier": {verifier},
		}, nil)
		require.Equal(t, http.StatusOK, status)
		require.Equal(t, "mock-access-token", body["access_token"])
	})

	for name, testCase := range map[string]struct {
		form      url.Values
		wantError string
	}{
		"unknown grant type": {
			form:      url.Values{"grant_type": {"password"}, "username": {"a"}},
			wantError: "unsupported_grant_type",
		},
		"absent grant type": {
			form:      url.Values{"code": {"code-1"}},
			wantError: "unsupported_grant_type",
		},
		"authorization code without a code": {
			form:      url.Values{"grant_type": {"authorization_code"}, "code_verifier": {verifier}},
			wantError: "invalid_request",
		},
		"pre-authorized code without the code": {
			form:      url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:pre-authorized_code"}},
			wantError: "invalid_request",
		},
		"missing PKCE verifier": {
			form:      url.Values{"grant_type": {"authorization_code"}, "code": {"code-1"}},
			wantError: "invalid_grant",
		},
		"malformed PKCE verifier": {
			form:      url.Values{"grant_type": {"authorization_code"}, "code": {"code-1"}, "code_verifier": {"too-short"}},
			wantError: "invalid_grant",
		},
		"PKCE verifier for another challenge": {
			form:      url.Values{"grant_type": {"authorization_code"}, "code": {"code-1"}, "code_verifier": {strings.Repeat("b", 43)}},
			wantError: "invalid_grant",
		},
	} {
		t.Run(name, func(t *testing.T) {
			status, body := postForm(t, tokenEndpoint, testCase.form, nil)
			require.Equal(t, http.StatusBadRequest, status)
			require.Equal(t, testCase.wantError, body["error"])
		})
	}
}

// TestTokenEndpointRequiresADPoPProofWhenConfigured covers HAIP §4
// ("Sender-constrained access token: MUST support DPoP") and the RFC 9449 §8
// nonce challenge.
func TestTokenEndpointRequiresADPoPProofWhenConfigured(t *testing.T) {
	config := DefaultOID4VCIIssuerConfig()
	config.RequireDPoP = true
	issuer := NewOID4VCIIssuerServer(config)
	defer issuer.Close()
	tokenEndpoint := issuer.URL() + "/token"
	signer := newMockIssuerTestSigner(t)
	form := url.Values{"grant_type": {"authorization_code"}, "code": {"code-1"}}

	status, body := postForm(t, tokenEndpoint, form, nil)
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, "invalid_dpop_proof", body["error"])

	status, body = postForm(t, tokenEndpoint, form, map[string]string{"DPoP": "not-a-jws"})
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, "invalid_dpop_proof", body["error"])

	status, body = postForm(t, tokenEndpoint, form, map[string]string{
		"DPoP": signer.dpopProof(t, http.MethodPost, issuer.URL()+"/credential", "", ""),
	})
	require.Equal(t, http.StatusBadRequest, status, "a proof bound to another endpoint is refused")
	require.Equal(t, "invalid_dpop_proof", body["error"])

	status, body = postForm(t, tokenEndpoint, form, map[string]string{
		"DPoP": signer.dpopProof(t, http.MethodPost, tokenEndpoint, "", ""),
	})
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, "mock-access-token", body["access_token"])
}

// TestCredentialEndpointRejectsWhatARealIssuerRejects covers the access token
// presentation (RFC 6750 §2.1 / RFC 9449 §7.1) and the §8.2.1.1 key proof
// rules: typ, aud, and the c_nonce an issuer with a Nonce Endpoint requires.
func TestCredentialEndpointRejectsWhatARealIssuerRejects(t *testing.T) {
	config := DefaultOID4VCIIssuerConfig()
	config.CredentialConfigurations = map[string]interface{}{
		"test-config": map[string]interface{}{
			"format": "jwt_vc_json",
			"proof_types_supported": map[string]interface{}{
				"jwt": map[string]interface{}{"proof_signing_alg_values_supported": []string{"ES256"}},
			},
		},
	}
	issuer := NewOID4VCIIssuerServer(config)
	defer issuer.Close()
	endpoint := issuer.URL() + "/credential"
	signer := newMockIssuerTestSigner(t)
	authorized := map[string]string{"Authorization": "Bearer " + issuer.AccessToken()}
	request := func(proof string) string {
		return `{"credential_configuration_id":"test-config","proofs":{"jwt":["` + proof + `"]}}`
	}

	t.Run("a proof with the issued nonce and the issuer audience is accepted", func(t *testing.T) {
		status, body := postJSON(t, endpoint, request(signer.keyProof(t, issuer.IssuerIdentifier(), "mock-nonce")), authorized)
		require.Equal(t, http.StatusOK, status)
		require.Contains(t, body, "credentials")
	})

	t.Run("the token must be presented with the scheme the token response named", func(t *testing.T) {
		status, body := postJSON(t, endpoint, request(signer.keyProof(t, issuer.IssuerIdentifier(), "mock-nonce")),
			map[string]string{"Authorization": "DPoP " + issuer.AccessToken()})
		require.Equal(t, http.StatusUnauthorized, status)
		require.Equal(t, "invalid_token", body["error"])

		status, body = postJSON(t, endpoint, request(signer.keyProof(t, issuer.IssuerIdentifier(), "mock-nonce")),
			map[string]string{"Authorization": "Bearer another-token"})
		require.Equal(t, http.StatusUnauthorized, status)
		require.Equal(t, "invalid_token", body["error"])
	})

	t.Run("a missing proof is refused when the configuration requires one", func(t *testing.T) {
		status, body := postJSON(t, endpoint, `{"credential_configuration_id":"test-config"}`, authorized)
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "invalid_proof", body["error"])
	})

	t.Run("the proof typ, aud and c_nonce are checked", func(t *testing.T) {
		wrongTyp := signer.sign(t, "JWT", map[string]any{"aud": issuer.IssuerIdentifier(), "iat": time.Now().Unix(), "nonce": "mock-nonce"})
		status, body := postJSON(t, endpoint, request(wrongTyp), authorized)
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "invalid_proof", body["error"])

		status, body = postJSON(t, endpoint, request(signer.keyProof(t, "https://another-issuer.example", "mock-nonce")), authorized)
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "invalid_proof", body["error"])

		status, body = postJSON(t, endpoint, request(signer.keyProof(t, issuer.IssuerIdentifier(), "")), authorized)
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "invalid_nonce", body["error"])

		status, body = postJSON(t, endpoint, request(signer.keyProof(t, issuer.IssuerIdentifier(), "stale-nonce")), authorized)
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "invalid_nonce", body["error"])
	})
}

// TestIssuerMetadataStatesTheConfiguredIdentifier pins that the document no
// longer echoes the request Host, so the §12.2.4 credential_issuer comparison
// can fail.
func TestIssuerMetadataStatesTheConfiguredIdentifier(t *testing.T) {
	config := DefaultOID4VCIIssuerConfig()
	config.CredentialIssuerIdentifier = "https://issuer.example"
	issuer := NewOID4VCIIssuerServer(config)
	defer issuer.Close()

	response, err := http.Get(issuer.URL() + "/.well-known/openid-credential-issuer")
	require.NoError(t, err)
	defer response.Body.Close()
	metadata := map[string]any{}
	require.NoError(t, json.NewDecoder(response.Body).Decode(&metadata))

	require.Equal(t, "https://issuer.example", metadata["credential_issuer"])
	// The endpoints stay reachable at the address the server listens on.
	require.Equal(t, issuer.URL()+"/credential", metadata["credential_endpoint"])

	unconfigured := NewOID4VCIIssuerServer(nil)
	defer unconfigured.Close()
	response, err = http.Get(unconfigured.URL() + "/.well-known/openid-credential-issuer")
	require.NoError(t, err)
	defer response.Body.Close()
	metadata = map[string]any{}
	require.NoError(t, json.NewDecoder(response.Body).Decode(&metadata))
	require.Equal(t, unconfigured.URL(), metadata["credential_issuer"])
}
