package oid4vp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/presenter/types"
)

func newEncryptionKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

// TestFinalResponseEncryptionRequiresJWKAlg covers OpenID4VP 1.0 §8.3: "The
// alg parameter MUST be present in the JWKs" and "The JWE alg algorithm used
// MUST be equal to the alg value of the chosen jwk". The draft-era
// authorization_encrypted_response_alg never stands in for a missing alg, on
// the Final profile as on HAIP.
func TestFinalResponseEncryptionRequiresJWKAlg(t *testing.T) {
	key := newEncryptionKey(t)
	metadata := &VerifierMetadata{
		AuthorizationEncryptedResponseAlg: "ECDH-ES",
		Jwks:                              jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "no-alg", Use: "enc"}}},
	}
	uri := finalQueryURI(url.Values{
		"client_id":       {"redirect_uri:https://verifier.example/response"},
		"response_type":   {"vp_token"},
		"response_mode":   {"direct_post.jwt"},
		"nonce":           {"n"},
		"client_metadata": {string(mustJSON(t, metadata))},
		"dcql_query":      {finalDcqlParam},
	})
	_, err := (&Oid4vpPresenter{}).ParsePresentationRequest(uri)
	require.True(t, errors.Is(err, ErrResponseEncryptionKeyUnusable), "want ErrResponseEncryptionKeyUnusable, got %v", err)

	_, err = encryptResponseForTest(&Oid4vpPresenter{}, map[string]any{"vp_token": map[string]any{}}, metadata)
	require.ErrorIs(t, err, ErrResponseEncryptionKeyUnusable)
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	require.NoError(t, err)
	return encoded
}

// draft24ResponseServer answers a Presentation Exchange response and hands the
// posted form to the test.
func draft24ResponseServer(t *testing.T) (*Oid4vpPresenter, url.URL, chan url.Values) {
	t.Helper()
	forms := make(chan url.Values, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		forms <- r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(server.Close)
	endpoint, err := url.Parse(server.URL)
	require.NoError(t, err)
	return &Oid4vpPresenter{HTTPClient: server.Client()}, *endpoint, forms
}

var draft24TestSubmission = types.PresentationSubmission{
	ID: "submission", DefinitionID: "definition",
	DescriptorMap: []types.DescriptorMapItem{{ID: "identity", Format: "vc+sd-jwt", Path: "$"}},
}

// TestDraft24DirectPostJWTFollowsJARM covers Draft 24 §8.3: the encrypted
// response uses JARM, whose alg and enc are the Verifier's
// authorization_encrypted_response_alg and authorization_encrypted_response_enc
// (A128CBC-HS256 when absent, JARM §3), encrypted to a client_metadata.jwks
// key usable for that alg.
func TestDraft24DirectPostJWTFollowsJARM(t *testing.T) {
	recipient := newEncryptionKey(t)
	signing, other := newEncryptionKey(t), newEncryptionKey(t)
	metadata := &VerifierMetadata{
		AuthorizationEncryptedResponseAlg: "ECDH-ES",
		// Only OpenID4VP 1.0 reads this list; JARM does not.
		EncryptedResponseEncValuesSupported: []string{"A256GCM"},
		Jwks: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &signing.PublicKey, KeyID: "signing", Use: "sig"},
			{Key: &other.PublicKey, KeyID: "other-alg", Algorithm: "ECDH-ES+A128KW"},
			{Key: &recipient.PublicKey, KeyID: "recipient"},
		}},
	}
	p, endpoint, forms := draft24ResponseServer(t)
	_, err := sendPresentationExchangeForTest(p, endpoint, []byte("credential~kb-jwt"), draft24TestSubmission, &types.PresentationRequest{
		State: "state", ResponseMode: string(OAuthAuthzReqResponseModeDirectPostJWT), ClientMetadata: metadata,
	})
	require.NoError(t, err)
	form := <-forms
	jwe, err := jose.ParseEncrypted(form.Get("response"), []jose.KeyAlgorithm{jose.ECDH_ES, jose.ECDH_ES_A128KW}, []jose.ContentEncryption{jose.A128CBC_HS256, jose.A128GCM, jose.A256GCM})
	require.NoError(t, err)
	require.Equal(t, "ECDH-ES", jwe.Header.Algorithm)
	require.Equal(t, "recipient", jwe.Header.KeyID, "the key with use sig and the key of another alg are never chosen")
	require.Equal(t, "A128CBC-HS256", jwe.Header.ExtraHeaders[jose.HeaderKey("enc")])
	plaintext, err := jwe.Decrypt(recipient)
	require.NoError(t, err)
	var payload map[string]any
	require.NoError(t, json.Unmarshal(plaintext, &payload))
	require.Equal(t, "credential~kb-jwt", payload["vp_token"])
	require.IsType(t, map[string]any{}, payload["presentation_submission"], "presentation_submission is the JSON object")
}

// TestDraft24JARMRefusesUnusableKeys: a key whose use is sig, or whose alg is
// not the requested one, is never an encryption key, and the first key is not
// taken in their place.
func TestDraft24JARMRefusesUnusableKeys(t *testing.T) {
	signing, other := newEncryptionKey(t), newEncryptionKey(t)
	for name, metadata := range map[string]*VerifierMetadata{
		"only a signing key": {
			AuthorizationEncryptedResponseAlg: "ECDH-ES",
			Jwks:                              jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &signing.PublicKey, KeyID: "signing", Use: "sig"}}},
		},
		"only another alg": {
			AuthorizationEncryptedResponseAlg: "ECDH-ES",
			Jwks:                              jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &other.PublicKey, KeyID: "other", Algorithm: "ECDH-ES+A128KW"}}},
		},
		"no authorization_encrypted_response_alg": {
			Jwks: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &other.PublicKey, KeyID: "other", Algorithm: "ECDH-ES", Use: "enc"}}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			p, endpoint, forms := draft24ResponseServer(t)
			_, err := sendPresentationExchangeForTest(p, endpoint, []byte("credential~kb-jwt"), draft24TestSubmission, &types.PresentationRequest{
				ResponseMode: string(OAuthAuthzReqResponseModeDirectPostJWT), ClientMetadata: metadata,
			})
			require.ErrorIs(t, err, ErrResponseEncryptionKeyUnusable)
			require.Empty(t, forms, "nothing is posted")
		})
	}
}

// TestDraft24PostsOnlyUnderDirectPostModes: the library answers a Draft 24
// request by POST only under direct_post and direct_post.jwt (Draft 24 §8.2,
// §8.3.1). A request without response_mode defaults to fragment, which is a
// redirect, never a POST.
func TestDraft24PostsOnlyUnderDirectPostModes(t *testing.T) {
	key := newEncryptionKey(t)
	for _, mode := range []string{"", "fragment", "query"} {
		t.Run("mode "+mode, func(t *testing.T) {
			p, endpoint, forms := draft24ResponseServer(t)
			_, err := sendPresentationExchangeForTest(p, endpoint, []byte("credential~kb-jwt"), draft24TestSubmission, &types.PresentationRequest{
				ResponseMode: mode,
				ClientMetadata: &VerifierMetadata{
					AuthorizationEncryptedResponseAlg: "ECDH-ES",
					Jwks:                              jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "enc", Use: "enc"}}},
				},
			})
			require.ErrorContains(t, err, "is not supported for a Presentation Exchange response")
			require.Empty(t, forms, "nothing is posted")
		})
	}
}

// Draft 24 §8.1: vp_token is "a JSON String or JSON object that MUST contain a
// single Verifiable Presentation or an array of JSON Strings and JSON objects".
// Encrypted under JARM (§8.3), the array of several SD-JWT presentations and
// an ldp_vp object stay JSON inside the JWE rather than the string of their
// encoding.
func TestDraft24JARMEmbedsStructuredVPTokenAsJSON(t *testing.T) {
	recipient := newEncryptionKey(t)
	metadata := &VerifierMetadata{
		AuthorizationEncryptedResponseAlg: "ECDH-ES",
		AuthorizationEncryptedResponseEnc: "A256GCM",
		Jwks:                              jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &recipient.PublicKey, KeyID: "recipient"}}},
	}
	for name, tc := range map[string]struct {
		vpToken string
		want    any
	}{
		"single compact presentation": {`credential~kb-jwt`, "credential~kb-jwt"},
		"array of presentations":      {`["one~kb","two~kb"]`, []any{"one~kb", "two~kb"}},
		"ldp_vp object":               {`{"type":["VerifiablePresentation"],"proof":{"type":"DataIntegrityProof"}}`, map[string]any{"type": []any{"VerifiablePresentation"}, "proof": map[string]any{"type": "DataIntegrityProof"}}},
	} {
		t.Run(name, func(t *testing.T) {
			p, endpoint, forms := draft24ResponseServer(t)
			_, err := sendPresentationExchangeForTest(p, endpoint, []byte(tc.vpToken), draft24TestSubmission, &types.PresentationRequest{
				ResponseMode: string(OAuthAuthzReqResponseModeDirectPostJWT), ClientMetadata: metadata,
			})
			require.NoError(t, err)
			jwe, err := jose.ParseEncrypted((<-forms).Get("response"), []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A256GCM})
			require.NoError(t, err)
			plaintext, err := jwe.Decrypt(recipient)
			require.NoError(t, err)
			var payload map[string]any
			require.NoError(t, json.Unmarshal(plaintext, &payload))
			require.Equal(t, tc.want, payload["vp_token"])
		})
	}
}
