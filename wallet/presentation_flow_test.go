package wallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/credential"
	credstoreTypes "github.com/trustknots/vcknots/wallet/credstore/types"
	"github.com/trustknots/vcknots/wallet/env"
	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	"github.com/trustknots/vcknots/wallet/serializer/plugins/jwtvc"
	"github.com/trustknots/vcknots/wallet/serializer/plugins/sdjwtvc"
)

// TestController_ParsePresentationRequest_RefusesMalformedRequests: a URI
// that is not an OpenID4VP Authorization Request, or one that lacks what the
// wallet needs to answer it (client_id, response_uri, dcql_query), is refused
// while parsing, before any credential is read.
func TestController_ParsePresentationRequest_RefusesMalformedRequests(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	for name, uri := range map[string]string{
		"empty URI":                          "",
		"invalid URI format":                 "invalid-uri-format",
		"unsupported scheme":                 "invalid://uri/with/malformed/parameters",
		"malformed query":                    "openid4vp://present?invalid[query",
		"http scheme":                        "http://example.com/present",
		"no client_id":                       "openid4vp://present?credential_id=test-cred&presentation_definition_id=test-def",
		"no dcql_query":                      "openid4vp://present?credential_id=test-cred&client_id=test-client",
		"no response endpoint":               "openid4vp://present?presentation_definition_id=test-def&client_id=test-client",
		"pre-standard credential_id":         "openid4vp://present?credential_id=non-existent-credential&presentation_definition_id=test&endpoint=https://example.com",
		"pre-standard credential_id list":    "openid4vp://present?credential_id=cred1&credential_id=cred2&presentation_definition_id=test&endpoint=https://example.com",
		"pre-standard escaped credential_id": "openid4vp://present?credential_id=cred%20with%20spaces&presentation_definition_id=test&endpoint=https://example.com",
	} {
		t.Run(name, func(t *testing.T) {
			request, err := controller.ParsePresentationRequest(t.Context(), uri)
			require.Nil(t, request)
			require.ErrorContains(t, err, "failed to parse request URI")
		})
	}
}

func TestController_ParsePresentationRequest_RejectsNonHTTPSResponseURI(t *testing.T) {
	controller := createTestControllerWithDefaults(t)

	dcqlQuery := url.QueryEscape(`{"credentials":[{"id":"cred1","format":"jwt_vc_json","meta":{"type_values":[["VerifiableCredential"]]}}]}`)
	// VP §5.9.3: with response_mode direct_post the redirect_uri: Client
	// Identifier is the Response URI, so the two must be the same value.
	uri := fmt.Sprintf(
		"openid4vp://present?client_id=redirect_uri:http://example.com/response&response_type=vp_token&nonce=test-nonce&dcql_query=%s&response_mode=direct_post&response_uri=http://example.com/response",
		dcqlQuery,
	)

	_, err := controller.ParsePresentationRequest(t.Context(), uri)
	require.Error(t, err)
	assert.ErrorContains(t, err, "response_uri must use https scheme")
}

// TestController_DefaultPresenterIgnoresTheHTTPEnvironment: plain http is an
// experimental relaxation a caller opts into in code (package experimental);
// the removed VCKNOTS_WALLET_HTTP_ALLOWED variable no longer relaxes the
// default presenter.
func TestController_DefaultPresenterIgnoresTheHTTPEnvironment(t *testing.T) {
	t.Setenv("VCKNOTS_WALLET_HTTP_ALLOWED", "true")
	controller := createTestControllerWithDefaults(t)
	dcqlQuery := url.QueryEscape(`{"credentials":[{"id":"cred1","format":"jwt_vc_json","meta":{"type_values":[["VerifiableCredential"]]}}]}`)
	uri := fmt.Sprintf(
		"openid4vp://present?client_id=redirect_uri:http://example.com/response&response_type=vp_token&nonce=test-nonce&dcql_query=%s&response_mode=direct_post&response_uri=http://example.com/response",
		dcqlQuery,
	)
	_, err := controller.ParsePresentationRequest(t.Context(), uri)
	assert.ErrorContains(t, err, "response_uri must use https scheme")
}

func TestController_ParsePresentationRequest_AllowsNonHTTPSResponseURI_WhenValidationDisabled(t *testing.T) {
	controller := createTestControllerAllowingHTTP(t)

	dcqlQuery := url.QueryEscape(`{"credentials":[{"id":"cred1","format":"jwt_vc_json","meta":{"type_values":[["VerifiableCredential"]]}}]}`)
	uri := fmt.Sprintf(
		"openid4vp://present?client_id=redirect_uri:http://example.com/response&response_type=vp_token&nonce=test-nonce&dcql_query=%s&response_mode=direct_post&response_uri=http://example.com/response",
		dcqlQuery,
	)

	request, err := controller.ParsePresentationRequest(t.Context(), uri)
	require.NoError(t, err)
	endpoint := request.ResponseEndpoint()
	require.NotNil(t, endpoint)
	assert.Equal(t, "http", endpoint.Scheme)
}

func TestController_ParsePresentationRequest_DirectPostJWTUsesResponseURI(t *testing.T) {
	controller := createTestControllerWithDefaults(t)
	dcqlQuery := url.QueryEscape(`{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test:identity"]},"claims":[{"path":["given_name"]}]}]}`)
	// direct_post.jwt is refused while parsing when the Verifier leaves no key
	// to encrypt the response to, so the request carries one.
	encryptionKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	clientMetadata, err := json.Marshal(map[string]any{
		"jwks": jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &encryptionKey.PublicKey, KeyID: "enc", Algorithm: "ECDH-ES", Use: "enc"}}},
	})
	require.NoError(t, err)
	uri := fmt.Sprintf(
		"openid4vp://present?client_id=redirect_uri:https://example.com/response&response_type=vp_token&nonce=test-nonce&dcql_query=%s&response_mode=direct_post.jwt&response_uri=https://example.com/response&client_metadata=%s",
		dcqlQuery, url.QueryEscape(string(clientMetadata)),
	)

	request, err := controller.ParsePresentationRequest(t.Context(), uri)
	require.NoError(t, err)
	endpoint := request.ResponseEndpoint()
	require.NotNil(t, endpoint)
	req := request.Request()
	require.NotNil(t, req.DcqlQuery)
	// VP §5.9.3: the Client Identifier binds response_uri, and the wallet
	// keeps the value there rather than in redirect_uri.
	assert.Equal(t, "https://example.com/response", req.ResponseURI)
	assert.Empty(t, req.RedirectURI)
	assert.Equal(t, "https://example.com/response", endpoint.String())
	assert.Equal(t, oid4vp.OAuthAuthzReqResponseModeDirectPostJWT, req.ResponseMode)
}

func TestWallet_SelectCredentialsForConsent(t *testing.T) {
	controller := createTestControllerWithDefaults(t)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	key := &realSigningKeyEntry{id: "holder-key-1", key: privateKey}

	rawCredential := buildTestSDJWTVC(t, key.PublicKey(), map[string]string{
		"given_name":  "TARO",
		"family_name": "TEST",
		"birthdate":   "2000-01-01",
	})
	err = controller.credStore.SaveCredentialEntry(credstoreTypes.CredentialEntry{
		Id:         "credential-1",
		ReceivedAt: time.Now(),
		Raw:        []byte(rawCredential),
		MimeType:   string(credential.SDJwtVC),
	}, 0)
	require.NoError(t, err)

	// direct_post.jwt is refused while parsing unless client_metadata names a
	// key the response can be encrypted to, so the request carries one.
	encryptionKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	clientMetadata, err := json.Marshal(map[string]any{
		"jwks": jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key:       &encryptionKey.PublicKey,
			KeyID:     "enc-key-1",
			Use:       "enc",
			Algorithm: "ECDH-ES",
		}}},
		"encrypted_response_enc_values_supported": []string{"A128GCM", "A256GCM"},
	})
	require.NoError(t, err)

	dcqlQuery := url.QueryEscape(`{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["given_name"]},{"path":["family_name"]}]}]}`)
	uri := fmt.Sprintf(
		"openid4vp://present?client_id=redirect_uri:https://example.com/response&response_type=vp_token&nonce=test-nonce&dcql_query=%s&response_mode=direct_post.jwt&response_uri=https://example.com/response&state=state-1&client_metadata=%s",
		dcqlQuery, url.QueryEscape(string(clientMetadata)),
	)

	request, err := controller.ParsePresentationRequest(t.Context(), uri)
	require.NoError(t, err)
	selections, err := controller.SelectCredentials(t.Context(), request)
	require.NoError(t, err)
	// The consent screen shows what SubmitPresentation would disclose: the
	// requested claims, and not birthdate.
	require.Equal(t, []CredentialSelection{{
		CredentialID:    "credential-1",
		QueryIDs:        []string{"pid"},
		DisclosedClaims: []string{"given_name", "family_name"},
	}}, selections)
}

func TestWallet_PresentDirectPostJWT(t *testing.T) {
	controller := createTestControllerAllowingHTTP(t)
	holderPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	holderKey := &realSigningKeyEntry{id: "holder-key-1", key: holderPrivateKey}

	rawCredential := buildTestSDJWTVC(t, holderKey.PublicKey(), map[string]string{
		"given_name":  "TARO",
		"family_name": "TEST",
		"birthdate":   "2000-01-01",
	})
	err = controller.credStore.SaveCredentialEntry(credstoreTypes.CredentialEntry{
		Id:         "credential-1",
		ReceivedAt: time.Now(),
		Raw:        []byte(rawCredential),
		MimeType:   string(credential.SDJwtVC),
	}, 0)
	require.NoError(t, err)

	encryptionPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	obs := newServerObservations(t, "response_uri")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		obs.called("response_uri")
		if !assert.Equal(obs, http.MethodPost, r.Method) {
			http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
			return
		}
		if !assert.NoError(obs, r.ParseForm()) {
			http.Error(w, "malformed authorization response form", http.StatusBadRequest)
			return
		}
		encryptedResponse := r.Form.Get("response")
		if !assert.NotEmpty(obs, encryptedResponse) {
			http.Error(w, "missing response parameter", http.StatusBadRequest)
			return
		}

		jwe, err := jose.ParseEncrypted(encryptedResponse, []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A128GCM})
		if !assert.NoError(obs, err) {
			http.Error(w, "response is not a JWE the verifier accepts", http.StatusBadRequest)
			return
		}
		plaintext, err := jwe.Decrypt(encryptionPrivateKey)
		if !assert.NoError(obs, err) {
			http.Error(w, "response cannot be decrypted", http.StatusBadRequest)
			return
		}
		var payload map[string]any
		if !assert.NoError(obs, json.Unmarshal(plaintext, &payload)) {
			http.Error(w, "response payload is not JSON", http.StatusBadRequest)
			return
		}
		obs.set("decrypted_payload", payload)
		_, _ = w.Write([]byte(`{"redirect_uri":"https://example.com/done"}`))
	}))
	defer server.Close()

	clientMetadataBytes, err := json.Marshal(map[string]any{
		"jwks": map[string]any{
			"keys": []jose.JSONWebKey{{
				Key:       &encryptionPrivateKey.PublicKey,
				KeyID:     "enc-key-1",
				Algorithm: "ECDH-ES",
				Use:       "enc",
			}},
		},
		"encrypted_response_enc_values_supported": []string{"A128GCM"},
	})
	require.NoError(t, err)

	dcqlQuery := url.QueryEscape(`{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},"claims":[{"path":["given_name"]}]}]}`)
	uri := fmt.Sprintf(
		"openid4vp://present?client_id=%s&response_type=vp_token&nonce=test-nonce&dcql_query=%s&response_mode=direct_post.jwt&response_uri=%s&state=state-1&client_metadata=%s",
		url.QueryEscape("redirect_uri:"+server.URL),
		dcqlQuery,
		url.QueryEscape(server.URL),
		url.QueryEscape(string(clientMetadataBytes)),
	)

	redirect, err := presentWithWalletChoice(t, controller, uri, holderKey, nil)
	require.NoError(t, err)
	assert.Equal(t, "https://example.com/done", redirect)
	decryptedPayload, _ := obs.get("decrypted_payload").(map[string]any)
	assert.Equal(t, "state-1", decryptedPayload["state"])
	vpToken, ok := decryptedPayload["vp_token"].(map[string]any)
	require.True(t, ok)
	require.NotEmpty(t, vpToken["pid"])
}

func TestApplyOID4VPRequestOptions(t *testing.T) {
	req := &oid4vp.CredentialPresentationRequest{
		OAuthAuthzRequest: &oid4vp.OAuthAuthzRequest{
			ClientID: "x509_san_dns:localhost",
			Nonce:    "request-nonce",
		},
	}

	t.Run("copies oid4vp request values into jwt-vc options", func(t *testing.T) {
		opts := &jwtvc.JwtVcPresentationOptions{
			Audience: "old-audience",
			Nonce:    "old-nonce",
		}

		applyOID4VPRequestOptions(req, opts)

		if opts.Audience != req.ClientID {
			t.Fatalf("expected audience %q, got %q", req.ClientID, opts.Audience)
		}
		if opts.Nonce != req.Nonce {
			t.Fatalf("expected nonce %q, got %q", req.Nonce, opts.Nonce)
		}
	})

	t.Run("copies oid4vp request values into sd-jwt options", func(t *testing.T) {
		opts := &sdjwtvc.SdJwtVcPresentationOptions{
			RequireKeyBinding: false,
			Audience:          "old-audience",
			Nonce:             "old-nonce",
		}

		applyOID4VPRequestOptions(req, opts)

		if opts.Audience != req.ClientID {
			t.Fatalf("expected audience %q, got %q", req.ClientID, opts.Audience)
		}
		if opts.Nonce != req.Nonce {
			t.Fatalf("expected nonce %q, got %q", req.Nonce, opts.Nonce)
		}
	})
}

func TestNewestCredentials_SelectsMostRecentEntries(t *testing.T) {
	now := time.Now()
	entries := []*SavedCredential{
		{Entry: &credstoreTypes.CredentialEntry{Id: "oldest", ReceivedAt: now.Add(-2 * time.Hour)}},
		{Entry: &credstoreTypes.CredentialEntry{Id: "newest", ReceivedAt: now}},
		{Entry: &credstoreTypes.CredentialEntry{Id: "middle", ReceivedAt: now.Add(-time.Hour)}},
	}

	selected := newestCredentials(entries, 1)
	require.Len(t, selected, 1)
	require.NotNil(t, selected[0])
	require.NotNil(t, selected[0].Entry)
	assert.Equal(t, "newest", selected[0].Entry.Id)
}

func TestNewestCredentials_ReturnsEntriesInDescendingReceivedAtOrder(t *testing.T) {
	now := time.Now()
	entries := []*SavedCredential{
		{Entry: &credstoreTypes.CredentialEntry{Id: "first", ReceivedAt: now.Add(-time.Minute)}},
		{Entry: &credstoreTypes.CredentialEntry{Id: "third", ReceivedAt: now.Add(-3 * time.Minute)}},
		{Entry: &credstoreTypes.CredentialEntry{Id: "second", ReceivedAt: now.Add(-2 * time.Minute)}},
	}

	selected := newestCredentials(entries, 2)
	require.Len(t, selected, 2)
	assert.Equal(t, "first", selected[0].Entry.Id)
	assert.Equal(t, "second", selected[1].Entry.Id)
}

func receiveCredentialForPresentationTest(t *testing.T) (*Wallet, *mockKeyEntry) {
	t.Helper()
	t.Setenv(env.DEBUG.String(), "")
	controller := createTestControllerAllowingHTTP(t)
	key := newMockKeyEntry()
	issuer := newReceiveCredentialTestServer(t, key)
	saved, err := receiveDraft13(t.Context(), controller,
		PreAuthorizedIssuanceRequest{CredentialOffer: preAuthorizedCodeOffer(issuer, "test-config", "test-code"), Acceptance: mockIssuerAcceptance()},
		CredentialRequest{HolderKeys: []IKeyEntry{key}})
	require.NoError(t, err, "presentation test must receive and store a real signed credential")
	require.NotNil(t, saved)
	require.NotEmpty(t, saved.Entry.Raw)
	return controller, key
}

func TestController_ReceiveThenPresent_ProfileWire(t *testing.T) {
	for _, draft := range []bool{false, true} {
		name := "final"
		if draft {
			name = "draft24"
		}
		t.Run(name, func(t *testing.T) {
			controller, key := receiveCredentialForPresentationTest(t)
			captured := make(chan url.Values, 1)
			obs := newServerObservations(t, "response_uri")
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				obs.called("response_uri")
				if !assert.NoError(obs, r.ParseForm()) {
					http.Error(w, "malformed authorization response form", http.StatusBadRequest)
					return
				}
				captured <- r.PostForm
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"redirect_uri":"https://verifier.example/done"}`))
			}))
			defer server.Close()
			params := url.Values{
				"client_id": {"redirect_uri:" + server.URL}, "response_uri": {server.URL},
				"response_type": {"vp_token"}, "response_mode": {"direct_post"},
				"nonce": {"test-nonce"}, "state": {"test-state"},
			}
			if draft {
				params.Set("scope", "openid")
				params.Set("presentation_definition", `{"id":"definition","input_descriptors":[{"id":"identity","format":{"jwt_vp_json":{"alg":["ES256"]}}}]}`)
			} else {
				params.Set("dcql_query", `{"credentials":[{"id":"identity","format":"jwt_vc_json","meta":{"type_values":[["VerifiableCredential"]]}}]}`)
			}
			uri := "openid4vp://present?" + params.Encode()
			parse := controller.ParsePresentationRequest
			if draft {
				parse = controller.Draft24().ParsePresentationRequest
			}
			request, err := parse(t.Context(), uri)
			require.NoError(t, err)
			selections, err := controller.SelectCredentials(t.Context(), request)
			require.NoError(t, err)
			result, err := controller.SubmitPresentation(t.Context(), request, Presentation{Key: key, Credentials: selections})
			require.NoError(t, err)
			require.Equal(t, "https://verifier.example/done", result.RedirectURI)
			var form url.Values
			select {
			case form = <-captured:
			default:
				t.Fatal("verifier received no presentation")
			}
			require.Equal(t, "test-state", form.Get("state"))
			var serialized string
			if draft {
				serialized = form.Get("vp_token")
				var submission struct {
					DefinitionID string `json:"definition_id"`
				}
				require.NoError(t, json.Unmarshal([]byte(form.Get("presentation_submission")), &submission))
				require.Equal(t, "definition", submission.DefinitionID)
			} else {
				require.NotContains(t, form, "presentation_submission")
				var response map[string][]string
				require.NoError(t, json.Unmarshal([]byte(form.Get("vp_token")), &response))
				require.Len(t, response["identity"], 1)
				serialized = response["identity"][0]
			}
			signed, err := jwt.ParseSigned(serialized, []jose.SignatureAlgorithm{jose.ES256})
			require.NoError(t, err)
			var claims map[string]any
			require.NoError(t, signed.Claims(key.PublicKey().Key, &claims))
			require.Equal(t, "test-nonce", claims["nonce"])
			vp, ok := claims["vp"].(map[string]any)
			require.True(t, ok)
			require.Len(t, vp["verifiableCredential"], 1)
		})
	}
}

// newReceiveCredentialTestServer is a plain-http Draft 13 issuer of one
// jwt_vc_json credential whose subject is holder's did:key, signed by the
// mockserver issuer key, for tests that need a stored credential.
func newReceiveCredentialTestServer(t *testing.T, holder IKeyEntry) *url.URL {
	t.Helper()
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	jwtBuilder := mockserver.MustNewJWTBuilder(mockserver.MustGenerateKeyPair("issuer-key-id"))
	credentialJWT, err := jwtBuilder.CreateSignedCredentialJWT(server.URL, map[string]any{
		"sub": didKeyOf(t, holder.PublicKey()),
		"vc": map[string]any{
			"@context":     []string{"https://www.w3.org/2018/credentials/v1"},
			"id":           "http://example.com/credential/1",
			"type":         []string{"VerifiableCredential"},
			"issuer":       server.URL,
			"issuanceDate": "2023-01-01T00:00:00Z",
			"credentialSubject": map[string]any{
				"id":   "http://example.com/subject",
				"name": "John Doe",
			},
		},
	})
	require.NoError(t, err)

	mux.HandleFunc("/.well-known/openid-credential-issuer", func(w http.ResponseWriter, _ *http.Request) {
		mockserver.JSONResponse(w, http.StatusOK, map[string]any{
			"credential_issuer":     server.URL,
			"credential_endpoint":   server.URL + "/credential",
			"authorization_servers": []string{server.URL},
			"credential_configurations_supported": map[string]any{
				"test-config": map[string]any{
					"format":                "jwt_vc_json",
					"credential_definition": map[string]any{"type": []string{"VerifiableCredential"}},
				},
			},
		})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		mockserver.JSONResponse(w, http.StatusOK, map[string]any{
			"issuer":         server.URL,
			"token_endpoint": server.URL + "/token",
			"pre-authorized_grant_anonymous_access_supported": true,
			"response_types_supported":                        []string{"code"},
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		mockserver.JSONResponse(w, http.StatusOK, map[string]any{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"c_nonce":      "test-nonce",
		})
	})
	mux.HandleFunc("/credential", func(w http.ResponseWriter, _ *http.Request) {
		mockserver.JSONResponse(w, http.StatusOK, map[string]any{"credential": credentialJWT})
	})

	issuer, err := url.Parse(server.URL)
	require.NoError(t, err)
	return issuer
}
