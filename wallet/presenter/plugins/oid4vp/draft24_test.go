package oid4vp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/presenter/types"
)

func TestPresentationRequest_ExplicitDraft24Boundary(t *testing.T) {
	p := &Oid4vpPresenter{}
	params := url.Values{
		"client_id":     {"redirect_uri:https://verifier.example/response"},
		"response_type": {"vp_token"}, "response_mode": {"fragment"}, "nonce": {"nonce"},
		"presentation_definition": {`{"id":"definition","input_descriptors":[{"id":"identity"}]}`},
	}
	draftURI := "openid4vp://present?" + params.Encode()
	draft, err := parseDraft24ForTest(p, draftURI)
	require.NoError(t, err)
	require.Equal(t, "definition", draft.PresentationDefinition.ID)
	require.Nil(t, draft.DcqlQuery)
	_, err = p.ParsePresentationRequest(draftURI)
	require.ErrorContains(t, err, "presentation_definition is not supported")

	params.Del("presentation_definition")
	params.Set("dcql_query", `{"credentials":[{"id":"identity","format":"dc+sd-jwt","meta":{"vct_values":["urn:identity"]},"claims":[{"path":["given_name"]}]}]}`)
	finalURI := "openid4vp://present?" + params.Encode()
	final, err := p.ParsePresentationRequest(finalURI)
	require.NoError(t, err)
	require.Nil(t, final.PresentationDefinition)
	require.Equal(t, "given_name", final.DcqlQuery.Credentials[0].Claims[0].Path[0])
	draftDCQL, err := parseDraft24ForTest(p, finalURI)
	require.NoError(t, err)
	require.Equal(t, final.DcqlQuery, draftDCQL.DcqlQuery)
}

func TestPresent_FinalAndDraft24WireResponses(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	submission := types.PresentationSubmission{
		ID: "submission", DefinitionID: "definition",
		DescriptorMap: []types.DescriptorMapItem{{ID: "identity", Format: "dc+sd-jwt", Path: "$"}},
	}
	for _, draft := range []bool{false, true} {
		for _, encrypted := range []bool{false, true} {
			name := "final"
			if draft {
				name = "draft24"
			}
			if encrypted {
				name += "_encrypted"
			} else {
				name += "_plain"
			}
			t.Run(name, func(t *testing.T) {
				captured := make(chan url.Values, 1)
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
						t.Errorf("unexpected request: %s, %s", r.Method, r.Header.Get("Content-Type"))
					}
					if err := r.ParseForm(); err != nil {
						t.Error(err)
					}
					captured <- r.PostForm
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"redirect_uri":"https://verifier.example/done"}`))
				}))
				defer server.Close()
				// Only this injected client trusts the test server's certificate.
				p := &Oid4vpPresenter{HTTPClient: server.Client()}
				endpoint, err := url.Parse(server.URL)
				require.NoError(t, err)
				request := &types.PresentationRequest{State: "state", CredentialQueryID: "identity"}
				if encrypted {
					request.ClientMetadata = &VerifierMetadata{
						AuthorizationEncryptedResponseAlg:   "ECDH-ES",
						AuthorizationEncryptedResponseEnc:   "A256GCM",
						EncryptedResponseEncValuesSupported: []string{"A256GCM"},
						Jwks:                                jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "recipient", Use: "enc", Algorithm: "ECDH-ES"}}},
					}
				}
				var redirect string
				if draft {
					redirect, err = sendPresentationExchangeForTest(p, *endpoint, []byte("credential~kb-jwt"), submission, request)
				} else {
					redirect, err = p.Present(types.Oid4vp, *endpoint, []byte("credential~kb-jwt"), request)
				}
				require.NoError(t, err)
				require.Equal(t, "https://verifier.example/done", redirect)
				form := <-captured
				payload := map[string]any{}
				if encrypted {
					require.Len(t, form, 1)
					jwe, err := jose.ParseEncrypted(form.Get("response"), []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A256GCM})
					require.NoError(t, err)
					plaintext, err := jwe.Decrypt(key)
					require.NoError(t, err)
					require.NoError(t, json.Unmarshal(plaintext, &payload))
				} else {
					require.NotContains(t, form, "response")
					payload["state"] = form.Get("state")
					if draft {
						payload["vp_token"] = form.Get("vp_token")
						var decoded any
						require.NoError(t, json.Unmarshal([]byte(form.Get("presentation_submission")), &decoded))
						payload["presentation_submission"] = decoded
					} else {
						require.NotContains(t, form, "presentation_submission")
						var decoded any
						require.NoError(t, json.Unmarshal([]byte(form.Get("vp_token")), &decoded))
						payload["vp_token"] = decoded
					}
				}
				require.Equal(t, "state", payload["state"])
				if draft {
					require.Equal(t, "credential~kb-jwt", payload["vp_token"])
					var encoded []byte
					if encrypted {
						// Draft 24 JARM carries presentation_submission as a JSON string.
						value, ok := payload["presentation_submission"].(string)
						require.True(t, ok)
						encoded = []byte(value)
					} else {
						encoded, err = json.Marshal(payload["presentation_submission"])
						require.NoError(t, err)
					}
					var actual types.PresentationSubmission
					require.NoError(t, json.Unmarshal(encoded, &actual))
					require.Equal(t, submission, actual)
				} else {
					require.Equal(t, map[string]any{"identity": []any{"credential~kb-jwt"}}, payload["vp_token"])
					require.NotContains(t, payload, "presentation_submission")
				}
			})
		}
	}
}

func TestDraft24ScopeCompatibility(t *testing.T) {
	params := url.Values{"client_id": {"redirect_uri:https://verifier.example/response"}, "response_type": {"vp_token"}, "response_mode": {"fragment"}, "nonce": {"n"}, "scope": {"openid"}, "presentation_definition": {`{"id":"definition"}`}}
	p := &Oid4vpPresenter{}
	_, err := parseDraft24ForTest(p, "openid4vp://present?"+params.Encode())
	require.NoError(t, err)
	params.Del("presentation_definition")
	params.Set("dcql_query", `{"credentials":[{"id":"identity","format":"dc+sd-jwt","meta":{}}]}`)
	_, err = p.ParsePresentationRequest("openid4vp://present?" + params.Encode())
	require.ErrorContains(t, err, "scope parameter is not supported")
}

func TestParseRequestRejectsInvalidOuterClientIDBeforeFetch(t *testing.T) {
	called := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called <- struct{}{}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()
	p := &Oid4vpPresenter{AllowHTTP: true}
	_, err := p.ParsePresentationRequest("openid4vp://present?client_id=origin:https://verifier.example&request_uri=" + url.QueryEscape(server.URL))
	require.Error(t, err)
	select {
	case <-called:
		t.Fatal("invalid outer client_id caused a request_uri fetch")
	default:
	}
}

func TestDraft24RetainsSyntacticDCQLParsing(t *testing.T) {
	params := url.Values{"client_id": {"redirect_uri:https://verifier.example/response"}, "response_type": {"vp_token"}, "response_mode": {"fragment"}, "nonce": {"n"}, "dcql_query": {`{"credentials":[{"id":"identity","format":"mso_mdoc"}]}`}}
	p := &Oid4vpPresenter{}
	request, err := parseDraft24ForTest(p, "openid4vp://present?"+params.Encode())
	require.NoError(t, err)
	require.Equal(t, "mso_mdoc", request.DcqlQuery.Credentials[0].Format)
	// Syntactic parsing is not evidence that mdoc presentation is implemented.
	_, err = p.ParsePresentationRequest("openid4vp://present?" + params.Encode())
	require.Error(t, err)
}

// TestParseDraft24KeepsRawPresentationDefinition pins that the Verifier's own
// Presentation Exchange definition survives parsing. This library models only
// its id, so a caller that has to render the requested input descriptors on a
// consent screen, or forward the definition, reads the wire value instead of
// re-encoding a lossy copy. It is request state, never an outgoing parameter.
func TestParseDraft24KeepsRawPresentationDefinition(t *testing.T) {
	definition := `{"id":"definition","input_descriptors":[{"id":"identity","constraints":{"fields":[{"path":["$.vct"]}]}}]}`
	p := &Oid4vpPresenter{}
	params := url.Values{
		"client_id":     {"redirect_uri:https://verifier.example/response"},
		"response_type": {"vp_token"}, "response_mode": {"fragment"}, "nonce": {"nonce"},
		"presentation_definition": {definition},
	}
	request, err := parseDraft24ForTest(p, "openid4vp://present?"+params.Encode())
	require.NoError(t, err)
	require.Equal(t, "definition", request.PresentationDefinition.ID)
	require.JSONEq(t, definition, string(request.RawPresentationDefinition))
	encoded, err := json.Marshal(request)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "input_descriptors")

	// A signed Request Object carries the definition as a JSON object rather
	// than as a query parameter string, and must round-trip the same way.
	f := newRequestObjectFixture(t, "verifier.example")
	signed, err := parseDraft24ForTest(f.presenter(), draft24RequestURI(t, f, draft24X509Claims(f)))
	require.NoError(t, err)
	require.JSONEq(t, `{"id":"pd-1","input_descriptors":[{"id":"pid"}]}`, string(signed.RawPresentationDefinition))

	// The Final path refuses presentation_definition outright, so it never
	// holds one.
	params.Del("presentation_definition")
	params.Set("dcql_query", `{"credentials":[{"id":"identity","format":"dc+sd-jwt","meta":{"vct_values":["urn:identity"]}}]}`)
	final, err := p.ParsePresentationRequest("openid4vp://present?" + params.Encode())
	require.NoError(t, err)
	require.Nil(t, final.RawPresentationDefinition)
}

// Draft24 Section 5.1 lets a Verifier name its Presentation Definition by
// reference (presentation_definition_uri) or through a scope instead of by
// value. Resolving either is the Wallet's step after admission, so parsing
// accepts the request and reports what arrived, unresolved.
func TestDraft24AcceptsPresentationDefinitionReferenceAtParse(t *testing.T) {
	base := func() url.Values {
		return url.Values{
			"client_id":     {"redirect_uri:https://verifier.example/response"},
			"response_type": {"vp_token"}, "response_mode": {"fragment"}, "nonce": {"nonce"},
		}
	}
	p := &Oid4vpPresenter{}

	t.Run("presentation_definition_uri", func(t *testing.T) {
		params := base()
		params.Set("presentation_definition_uri", "https://verifier.example/pd/1")
		req, err := parseDraft24ForTest(p, "openid4vp://present?"+params.Encode())
		require.NoError(t, err)
		require.Equal(t, "https://verifier.example/pd/1", req.PresentationDefinitionURI)
		require.Nil(t, req.PresentationDefinition)
		require.Nil(t, req.DcqlQuery)
	})

	t.Run("scope", func(t *testing.T) {
		params := base()
		params.Set("scope", "com.example.pid")
		req, err := parseDraft24ForTest(p, "openid4vp://present?"+params.Encode())
		require.NoError(t, err)
		require.Equal(t, "com.example.pid", req.Scope)
		require.Nil(t, req.PresentationDefinition)
		require.Empty(t, req.PresentationDefinitionURI)
	})

	t.Run("none of them", func(t *testing.T) {
		_, err := parseDraft24ForTest(p, "openid4vp://present?"+base().Encode())
		assertAuthzErrorCode(t, err, InvalidRequestError)
		require.ErrorContains(t, err, "presentation_definition, presentation_definition_uri, scope or dcql_query is required")
	})
}
