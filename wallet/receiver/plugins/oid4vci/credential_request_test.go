package oid4vci

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
	"github.com/trustknots/vcknots/wallet/receiver/types"
)

func TestOid4vciReceiver_FinalPrimitives(t *testing.T) {
	receiver := &Oid4vciReceiver{}

	receiver.AllowHTTP = true

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/challenge":
			if r.Method != http.MethodPost {
				t.Errorf("challenge method = %s", r.Method)
			}
			mockserver.JSONResponse(w, http.StatusOK, map[string]string{"attestation_challenge": "challenge-1"})
		case "/par":
			if r.Method != http.MethodPost {
				t.Errorf("PAR method = %s", r.Method)
			}
			if got := r.Header.Get("OAuth-Client-Attestation"); got != "attestation-jwt" {
				t.Errorf("OAuth-Client-Attestation = %q", got)
			}
			if got := r.Header.Get("OAuth-Client-Attestation-PoP"); got != "pop-jwt" {
				t.Errorf("OAuth-Client-Attestation-PoP = %q", got)
			}
			if err := r.ParseForm(); err != nil {
				t.Fatalf("failed to parse PAR form: %v", err)
			}
			if got := r.Form.Get("grant_type"); got != "" {
				t.Errorf("PAR should not include grant_type, got %q", got)
			}
			if got := r.Form.Get("issuer_state"); got != "issuer-state-1" {
				t.Errorf("issuer_state = %q", got)
			}
			mockserver.JSONResponse(w, http.StatusCreated, map[string]any{"request_uri": "urn:request:1", "expires_in": 60})
		case "/token":
			if got := r.Header.Get("DPoP"); got != "dpop-token" {
				t.Errorf("DPoP header = %q", got)
			}
			if err := r.ParseForm(); err != nil {
				t.Fatalf("failed to parse token form: %v", err)
			}
			if got := r.Form.Get("grant_type"); got != "authorization_code" {
				t.Errorf("grant_type = %q", got)
			}
			if got := r.Form.Get("code_verifier"); got != "verifier-1" {
				t.Errorf("code_verifier = %q", got)
			}
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{"access_token": "access-1", "token_type": "DPoP"})
		case "/nonce":
			mockserver.JSONResponse(w, http.StatusOK, map[string]string{"c_nonce": "nonce-1"})
		case "/credential":
			assertBearerJSONRequest(t, r, "access-1", "dpop-credential")
			var body types.CredentialRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("failed to decode credential request: %v", err)
			}
			if body.CredentialConfigurationID != "pid" {
				t.Errorf("credential_configuration_id = %q", body.CredentialConfigurationID)
			}
			if body.Proofs == nil || len(body.Proofs.JWT) != 1 || body.Proofs.JWT[0] != "proof-jwt" {
				t.Errorf("proofs.jwt = %#v", body.Proofs)
			}
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{"transaction_id": "tx-1"})
		case "/deferred":
			assertBearerJSONRequest(t, r, "access-1", "dpop-deferred")
			var body types.DeferredCredentialRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("failed to decode deferred request: %v", err)
			}
			if body.TransactionID != "tx-1" {
				t.Errorf("transaction_id = %q", body.TransactionID)
			}
			mockserver.JSONResponse(w, http.StatusOK, map[string]any{"credential": "credential-jwt", "notification_id": "notification-1"})
		case "/notification":
			assertBearerJSONRequest(t, r, "access-1", "dpop-notification")
			var body types.NotificationRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("failed to decode notification request: %v", err)
			}
			if body.NotificationID != "notification-1" || body.Event != "credential_accepted" {
				t.Errorf("notification body = %#v", body)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	endpoint := func(path string) common.URIField {
		t.Helper()
		parsed, err := url.Parse(server.URL + path)
		if err != nil {
			t.Fatalf("failed to parse endpoint: %v", err)
		}
		return common.URIField(*parsed)
	}

	challenge, err := receiver.FetchClientAttestationChallenge(t.Context(), endpoint("/challenge"))
	if err != nil {
		t.Fatalf("FetchClientAttestationChallenge() error = %v", err)
	}
	if challenge.AttestationChallenge != "challenge-1" {
		t.Fatalf("challenge = %#v", challenge)
	}

	par, err := receiver.PushAuthorizationRequest(t.Context(), endpoint("/par"), types.PushedAuthorizationRequest{
		ResponseType:        "code",
		ClientID:            "client-1",
		RedirectURI:         "https://wallet.example/callback",
		Scope:               "pid_scope",
		State:               "state-1",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
		IssuerState:         "issuer-state-1",
	}, types.ClientAuthentication{ClientAttestation: fixedAttestationHeaders(types.OAuthClientAttestationHeaders{
		ClientAttestation:    "attestation-jwt",
		ClientAttestationPop: "pop-jwt",
	})})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest() error = %v", err)
	}
	if par.RequestURI != "urn:request:1" || par.ExpiresIn != 60 {
		t.Fatalf("PAR response = %#v", par)
	}

	token, err := receiver.RequestToken(t.Context(), endpoint("/token"), types.TokenRequest{
		GrantType:    types.AuthorizationCode,
		Code:         "code-1",
		RedirectURI:  "https://wallet.example/callback",
		CodeVerifier: "verifier-1",
		ClientID:     "client-1",
	}, types.ClientAuthentication{ClientAttestation: fixedAttestationHeaders(types.OAuthClientAttestationHeaders{}), DPoP: fixedProof("dpop-token")})
	if err != nil {
		t.Fatalf("token request error = %v", err)
	}
	if token.Token != "access-1" || token.TokenType != "DPoP" {
		t.Fatalf("token response = %#v", token)
	}

	nonce, err := receiver.RequestNonce(t.Context(), endpoint("/nonce"))
	if err != nil {
		t.Fatalf("FetchNonce() error = %v", err)
	}
	if nonce.CNonce != "nonce-1" {
		t.Fatalf("nonce response = %#v", nonce)
	}

	credential, err := requestCredentialJSON(t.Context(), receiver, endpoint("/credential"), "access-1", types.CredentialRequest{
		CredentialConfigurationID: "pid",
		Proofs:                    &types.CredentialProofs{JWT: []string{"proof-jwt"}},
	}, fixedProof("dpop-credential"))
	if err != nil {
		t.Fatalf("credential request error = %v", err)
	}
	if credential.TransactionID != "tx-1" {
		t.Fatalf("credential response = %#v", credential)
	}

	deferred, err := requestCredentialJSON(t.Context(), receiver, endpoint("/deferred"), "access-1", types.DeferredCredentialRequest{TransactionID: credential.TransactionID}, fixedProof("dpop-deferred"))
	if err != nil {
		t.Fatalf("deferred credential request error = %v", err)
	}
	if deferred.Credential != "credential-jwt" || deferred.NotificationID != "notification-1" {
		t.Fatalf("deferred response = %#v", deferred)
	}

	if err := receiver.SendNotification(t.Context(), endpoint("/notification"), dpopAccessToken("access-1"), types.NotificationRequest{
		NotificationID: deferred.NotificationID,
		Event:          "credential_accepted",
	}, fixedProof("dpop-notification")); err != nil {
		t.Fatalf("notification error = %v", err)
	}
}

func TestOid4vciReceiver_CredentialRequestAndResponseEncryption(t *testing.T) {
	receiver := &Oid4vciReceiver{}
	recipient, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate recipient key: %v", err)
	}
	metadata := &types.CredentialIssuerMetadata{
		CredentialRequestEncryption: &types.CredentialRequestEncryption{
			Jwks: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
				{
					Key:       &recipient.PublicKey,
					KeyID:     "issuer-enc-key",
					Use:       "enc",
					Algorithm: string(jose.ECDH_ES),
				},
			}},
			EncValuesSupported: []string{"A256GCM"},
		},
	}

	body, contentType, err := receiver.EncodeCredentialRequest(types.CredentialRequest{
		CredentialConfigurationID: "pid",
		Proofs:                    &types.CredentialProofs{JWT: []string{"proof-jwt"}},
	}, metadata)
	if err != nil {
		t.Fatalf("EncodeCredentialRequest() error = %v", err)
	}
	if contentType != "application/jwt" {
		t.Fatalf("contentType = %q", contentType)
	}
	jwe, err := jose.ParseEncrypted(string(body), []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		t.Fatalf("failed to parse request JWE: %v", err)
	}
	if jwe.Header.KeyID != "issuer-enc-key" {
		t.Fatalf("kid = %q", jwe.Header.KeyID)
	}
	if got := jwe.Header.ExtraHeaders[jose.HeaderContentType]; got != "json" {
		t.Fatalf("cty = %#v", got)
	}
	plaintext, err := jwe.Decrypt(recipient)
	if err != nil {
		t.Fatalf("failed to decrypt request JWE: %v", err)
	}
	var decodedRequest types.CredentialRequest
	if err := json.Unmarshal(plaintext, &decodedRequest); err != nil {
		t.Fatalf("failed to decode request: %v", err)
	}
	if decodedRequest.CredentialConfigurationID != "pid" || decodedRequest.Proofs.JWT[0] != "proof-jwt" {
		t.Fatalf("decoded request = %#v", decodedRequest)
	}

	responsePayload, err := json.Marshal(types.CredentialResponse{Credential: "credential-jwt", NotificationID: "notification-1"})
	if err != nil {
		t.Fatalf("failed to marshal response: %v", err)
	}
	encrypter, err := jose.NewEncrypter(
		jose.A256GCM,
		jose.Recipient{Algorithm: jose.ECDH_ES, Key: &recipient.PublicKey, KeyID: "wallet-enc-key"},
		(&jose.EncrypterOptions{}).WithContentType("json"),
	)
	if err != nil {
		t.Fatalf("failed to create encrypter: %v", err)
	}
	encryptedResponse, err := encrypter.Encrypt(responsePayload)
	if err != nil {
		t.Fatalf("failed to encrypt response: %v", err)
	}
	serializedResponse, err := encryptedResponse.CompactSerialize()
	if err != nil {
		t.Fatalf("failed to serialize response: %v", err)
	}

	decodedResponse, err := receiver.DecodeCredentialResponse([]byte(serializedResponse), "application/jwt", recipient, false)
	if err != nil {
		t.Fatalf("DecodeCredentialResponse() error = %v", err)
	}
	if decodedResponse.Credential != "credential-jwt" || decodedResponse.NotificationID != "notification-1" {
		t.Fatalf("decoded response = %#v", decodedResponse)
	}

	plainResponse, err := receiver.DecodeCredentialResponse([]byte(`{"transaction_id":"tx-1"}`), "application/json", nil, false)
	if err != nil {
		t.Fatalf("DecodeCredentialResponse() plain error = %v", err)
	}
	if plainResponse.TransactionID != "tx-1" {
		t.Fatalf("plain response = %#v", plainResponse)
	}
}

func assertBearerJSONRequest(t *testing.T, r *http.Request, accessToken string, dpopProof string) {
	t.Helper()
	if r.Method != http.MethodPost {
		t.Errorf("method = %s", r.Method)
	}
	if got := r.Header.Get("Authorization"); got != "DPoP "+accessToken {
		t.Errorf("Authorization header = %q", got)
	}
	if got := r.Header.Get("DPoP"); got != dpopProof {
		t.Errorf("DPoP header = %q", got)
	}
	if got := r.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type header = %q", got)
	}
}

func TestOid4vciReceiver_ReceiveCredential(t *testing.T) {
	// Create mock OID4VCI issuer server (which serves credential endpoint)
	issuer := mockserver.NewOID4VCIIssuerServer(nil)
	defer issuer.Close()

	// The issuer only accepts the token it issued, as a real one does.
	accessToken := types.CredentialIssuanceAccessToken{Token: issuer.AccessToken(), TokenType: issuer.TokenType()}

	serverURL, _ := url.Parse(issuer.URL() + "/credential")
	endpoint := common.URIField(*serverURL)

	t.Run("https is required", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		receiver.AllowHTTP = false

		_, err := receiver.ReceiveCredential(types.Oid4vci, endpoint, "test-config", nil, accessToken, nil, nil)
		if err == nil {
			t.Fatal("ReceiveCredential should be error when issuer's schema is http")
		}
	})

	t.Run("Happy path", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		receiver.AllowHTTP = true

		credential, err := receiver.ReceiveCredential(types.Oid4vci, endpoint, "test-config", nil, accessToken, nil, nil)
		if err != nil {
			t.Fatalf("Expected no error, got %v", err)
		}
		if credential == nil || *credential == "" {
			t.Fatal("Expected credential, got empty string")
		}

		// The mock server returns a default JWT credential
		if !strings.HasPrefix(*credential, "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9") {
			t.Errorf("Expected JWT credential to start with header, got %s", (*credential)[:50])
		}
	})

	t.Run("Request uses credential_configuration_id and proofs", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		captureServer := mockserver.NewMockServer()
		defer captureServer.Close()

		var capturedBody map[string]interface{}
		handlerErrCh := make(chan error, 1)
		captureServer.HandleFunc("/credential", func(w http.ResponseWriter, r *http.Request) {
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				handlerErrCh <- fmt.Errorf("failed to read request body: %w", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			if err := json.Unmarshal(bodyBytes, &capturedBody); err != nil {
				handlerErrCh <- fmt.Errorf("failed to parse request body: %w", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			handlerErrCh <- nil

			mockserver.JSONResponse(w, http.StatusOK, map[string]interface{}{
				"credentials": []map[string]string{{
					"credential": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
				}},
			})
		})

		captureURL, _ := url.Parse(captureServer.URL() + "/credential")
		captureEndpoint := common.URIField(*captureURL)
		proof := "eyJhbGciOiJFUzI1NiJ9.eyJub25jZSI6InRlc3QifQ.signature"

		credential, err := receiver.ReceiveCredential(types.Oid4vci, captureEndpoint, "test-config", nil, accessToken, nil, &proof)
		require.NoError(t, err)
		require.NotNil(t, credential)
		require.NotEmpty(t, *credential)
		require.NoError(t, <-handlerErrCh)

		_, exists := capturedBody["format"]
		assert.False(t, exists, "format should not be present in credential request body")
		_, exists = capturedBody["proof"]
		assert.False(t, exists, "proof should not be present in credential request body")

		credentialConfigurationID, ok := capturedBody["credential_configuration_id"].(string)
		require.True(t, ok, "credential_configuration_id must be present as string")
		assert.Equal(t, "test-config", credentialConfigurationID)

		proofs, ok := capturedBody["proofs"].(map[string]interface{})
		require.True(t, ok, "proofs must be present as object")
		jwtProofs, ok := proofs["jwt"].([]interface{})
		require.True(t, ok, "proofs.jwt must be present as array")
		require.Len(t, jwtProofs, 1, "proofs.jwt must contain one JWT value")
		assert.Equal(t, proof, jwtProofs[0])
	})

	t.Run("Request omits proof fields when jwt proof is not provided", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		captureServer := mockserver.NewMockServer()
		defer captureServer.Close()

		var capturedBody map[string]interface{}
		handlerErrCh := make(chan error, 1)
		captureServer.HandleFunc("/credential", func(w http.ResponseWriter, r *http.Request) {
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				handlerErrCh <- fmt.Errorf("failed to read request body: %w", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			if err := json.Unmarshal(bodyBytes, &capturedBody); err != nil {
				handlerErrCh <- fmt.Errorf("failed to parse request body: %w", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			handlerErrCh <- nil

			mockserver.JSONResponse(w, http.StatusOK, map[string]interface{}{
				"credentials": []map[string]string{{
					"credential": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
				}},
			})
		})

		captureURL, _ := url.Parse(captureServer.URL() + "/credential")
		captureEndpoint := common.URIField(*captureURL)

		credential, err := receiver.ReceiveCredential(types.Oid4vci, captureEndpoint, "test-config", nil, accessToken, nil, nil)
		require.NoError(t, err)
		require.NotNil(t, credential)
		require.NotEmpty(t, *credential)
		require.NoError(t, <-handlerErrCh)

		credentialConfigurationID, ok := capturedBody["credential_configuration_id"].(string)
		require.True(t, ok, "credential_configuration_id must be present as string")
		assert.Equal(t, "test-config", credentialConfigurationID)

		_, exists := capturedBody["proof"]
		assert.False(t, exists, "proof should not be present in credential request body")
		_, exists = capturedBody["proofs"]
		assert.False(t, exists, "proofs should not be present when proof is not provided")
		_, exists = capturedBody["format"]
		assert.False(t, exists, "format should not be present in credential request body")
	})

	t.Run("DPoP access token sends DPoP authorization and proof headers", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		captureServer := mockserver.NewMockServer()
		defer captureServer.Close()

		dpopProof := "dpop.proof.jwt"
		dpopAccessToken := types.CredentialIssuanceAccessToken{
			Token:     "dpop-access-token",
			TokenType: "DPoP",
		}
		handlerErrCh := make(chan error, 1)
		captureServer.HandleFunc("/credential", func(w http.ResponseWriter, r *http.Request) {
			if got := r.Header.Get("Authorization"); got != "DPoP dpop-access-token" {
				handlerErrCh <- fmt.Errorf("Authorization header = %q", got)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if got := r.Header.Get("DPoP"); got != dpopProof {
				handlerErrCh <- fmt.Errorf("DPoP header = %q", got)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			handlerErrCh <- nil

			mockserver.JSONResponse(w, http.StatusOK, map[string]interface{}{
				"credentials": []map[string]string{{
					"credential": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
				}},
			})
		})

		captureURL, _ := url.Parse(captureServer.URL() + "/credential")
		captureEndpoint := common.URIField(*captureURL)

		credential, err := receiver.ReceiveCredential(
			types.Oid4vci,
			captureEndpoint,
			"test-config",
			nil,
			dpopAccessToken,
			nil,
			nil,
			&types.CredentialRequestOptions{DPoPProofJWT: &dpopProof},
		)
		require.NoError(t, err)
		require.NotNil(t, credential)
		require.NoError(t, <-handlerErrCh)
	})

	t.Run("use_dpop_nonce error is returned as sentinel error", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		captureServer := mockserver.NewMockServer()
		defer captureServer.Close()

		dpopProof := "dpop.proof.jwt"
		dpopAccessToken := types.CredentialIssuanceAccessToken{
			Token:     "dpop-access-token",
			TokenType: "DPoP",
		}
		captureServer.HandleFunc("/credential", func(w http.ResponseWriter, r *http.Request) {
			mockserver.JSONResponse(w, http.StatusBadRequest, map[string]string{
				"error": "use_dpop_nonce",
			})
		})

		captureURL, _ := url.Parse(captureServer.URL() + "/credential")
		captureEndpoint := common.URIField(*captureURL)

		_, err := receiver.ReceiveCredential(
			types.Oid4vci,
			captureEndpoint,
			"test-config",
			nil,
			dpopAccessToken,
			nil,
			nil,
			&types.CredentialRequestOptions{DPoPProofJWT: &dpopProof},
		)
		require.Error(t, err)
		assert.ErrorIs(t, err, types.ErrUseDPoPNonce)
	})

	t.Run("DPoP access token skips nil request options", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		captureServer := mockserver.NewMockServer()
		defer captureServer.Close()

		dpopProof := "dpop.proof.jwt"
		dpopAccessToken := types.CredentialIssuanceAccessToken{
			Token:     "dpop-access-token",
			TokenType: "DPoP",
		}
		handlerErrCh := make(chan error, 1)
		captureServer.HandleFunc("/credential", func(w http.ResponseWriter, r *http.Request) {
			if got := r.Header.Get("DPoP"); got != dpopProof {
				handlerErrCh <- fmt.Errorf("DPoP header = %q", got)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			handlerErrCh <- nil

			mockserver.JSONResponse(w, http.StatusOK, map[string]interface{}{
				"credentials": []map[string]string{{
					"credential": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
				}},
			})
		})

		captureURL, _ := url.Parse(captureServer.URL() + "/credential")
		captureEndpoint := common.URIField(*captureURL)

		credential, err := receiver.ReceiveCredential(
			types.Oid4vci,
			captureEndpoint,
			"test-config",
			nil,
			dpopAccessToken,
			nil,
			nil,
			nil,
			&types.CredentialRequestOptions{DPoPProofJWT: &dpopProof},
		)
		require.NoError(t, err)
		require.NotNil(t, credential)
		require.NoError(t, <-handlerErrCh)
	})

	t.Run("Request uses credential_identifier when provided", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		captureServer := mockserver.NewMockServer()
		defer captureServer.Close()

		var capturedBody map[string]interface{}
		handlerErrCh := make(chan error, 1)
		captureServer.HandleFunc("/credential", func(w http.ResponseWriter, r *http.Request) {
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				handlerErrCh <- fmt.Errorf("failed to read request body: %w", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			if err := json.Unmarshal(bodyBytes, &capturedBody); err != nil {
				handlerErrCh <- fmt.Errorf("failed to parse request body: %w", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			handlerErrCh <- nil

			mockserver.JSONResponse(w, http.StatusOK, map[string]interface{}{
				"credentials": []map[string]string{{
					"credential": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature",
				}},
			})
		})

		captureURL, _ := url.Parse(captureServer.URL() + "/credential")
		captureEndpoint := common.URIField(*captureURL)
		credentialIdentifier := "cred-id-1"

		credential, err := receiver.ReceiveCredential(types.Oid4vci, captureEndpoint, "test-config", &credentialIdentifier, accessToken, nil, nil)
		require.NoError(t, err)
		require.NotNil(t, credential)
		require.NotEmpty(t, *credential)
		require.NoError(t, <-handlerErrCh)

		identifier, ok := capturedBody["credential_identifier"].(string)
		require.True(t, ok, "credential_identifier must be present as string")
		assert.Equal(t, credentialIdentifier, identifier)

		_, exists := capturedBody["credential_configuration_id"]
		assert.False(t, exists, "credential_configuration_id should not be present when credential_identifier is used")
	})

	t.Run("Server error", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		receiver.AllowHTTP = true

		// Create a separate server for error testing
		errorServer := mockserver.NewMockServer()
		defer errorServer.Close()

		errorServer.SetErrorResponse("/credential", http.StatusInternalServerError)

		errorURL, _ := url.Parse(errorServer.URL())
		_, err := receiver.ReceiveCredential(types.Oid4vci, common.URIField(*errorURL), "test-config", nil, accessToken, nil, nil)
		if err == nil {
			t.Fatal("Expected error for server error")
		}
	})

	t.Run("Invalid JSON response", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		receiver.AllowHTTP = true

		invalidJSONServer := mockserver.NewMockServer()
		defer invalidJSONServer.Close()

		invalidJSONServer.SetTextResponse("/credential", http.StatusOK, "{invalid-json")

		invalidJSONURL, _ := url.Parse(invalidJSONServer.URL())
		_, err := receiver.ReceiveCredential(types.Oid4vci, common.URIField(*invalidJSONURL), "test-config", nil, accessToken, nil, nil)
		if err == nil {
			t.Fatal("Expected error for invalid JSON response")
		}
	})

	t.Run("No credential in response", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		receiver.AllowHTTP = true

		noCredServer := mockserver.NewMockServer()
		defer noCredServer.Close()

		// Return valid JSON but without credential field
		noCredServer.SetJSONResponse("/credential", http.StatusOK, map[string]string{"status": "success"})

		noCredURL, _ := url.Parse(noCredServer.URL())
		_, err := receiver.ReceiveCredential(types.Oid4vci, common.URIField(*noCredURL), "test-config", nil, accessToken, nil, nil)
		if err == nil {
			t.Fatal("Expected error when no credential is present in the response")
		}
	})

	t.Run("Multiple credentials in response", func(t *testing.T) {
		receiver := &Oid4vciReceiver{AllowHTTP: true}

		multiCredServer := mockserver.NewMockServer()
		defer multiCredServer.Close()

		multiCredServer.SetJSONResponse("/credential", http.StatusOK, map[string]interface{}{
			"credentials": []map[string]string{
				{"credential": "cred-1"},
				{"credential": "cred-2"},
			},
		})

		multiCredURL, _ := url.Parse(multiCredServer.URL())
		_, err := receiver.ReceiveCredential(types.Oid4vci, common.URIField(*multiCredURL), "test-config", nil, accessToken, nil, nil)
		if err == nil {
			t.Fatal("Expected error when multiple credentials are present in the response")
		}
	})
}
