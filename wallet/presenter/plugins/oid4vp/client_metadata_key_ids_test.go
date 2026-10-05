package oid4vp

import (
	"encoding/json"
	"errors"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/experimental"
	"github.com/trustknots/vcknots/wallet/presenter/types"
)

// publicEncryptionJWK is the fixture response encryption key as a JSON member
// of client_metadata.jwks.keys, with kid set to keyID or left out when empty.
func publicEncryptionJWK(t *testing.T, keyID string) map[string]any {
	t.Helper()
	metadata := responseEncryptionMetadata()
	encoded, err := json.Marshal(metadata.Jwks.Keys[0])
	require.NoError(t, err)
	var member map[string]any
	require.NoError(t, json.Unmarshal(encoded, &member))
	delete(member, "kid")
	if keyID != "" {
		member["kid"] = keyID
	}
	return member
}

// clientMetadataKeySets are the client_metadata.jwks shapes the kid rule of
// OpenID4VP 1.0 Section 5.1 tells apart. want is the refusal on the 1.0 entry
// points; with the experimental relaxation, and on Draft 24, every one is
// accepted.
func clientMetadataKeySets(t *testing.T) []struct {
	name string
	keys []any
	want error
} {
	unknownKeyType := map[string]any{"kty": "XYZ", "use": "enc"}
	return []struct {
		name string
		keys []any
		want error
	}{
		{name: "every key has a unique kid", keys: []any{publicEncryptionJWK(t, "enc-1"), publicEncryptionJWK(t, "enc-2")}},
		{name: "no jwks at all", keys: nil},
		{name: "a key without kid", keys: []any{publicEncryptionJWK(t, "enc-1"), publicEncryptionJWK(t, "")}, want: ErrClientMetadataJWKKeyIDMissing},
		{name: "an empty kid", keys: []any{map[string]any{"kty": "EC", "kid": ""}}, want: ErrClientMetadataJWKKeyIDMissing},
		{name: "a kid that is not a string", keys: []any{map[string]any{"kty": "EC", "kid": 7}}, want: ErrClientMetadataJWKKeyIDMissing},
		// The decode drops a key it cannot use (RFC 7517 Section 5), but the
		// Section 5.1 rule is about every JWK in the set.
		{name: "an unusable key without kid", keys: []any{publicEncryptionJWK(t, "enc-1"), unknownKeyType}, want: ErrClientMetadataJWKKeyIDMissing},
		{name: "a member that is not an object", keys: []any{"not-a-jwk"}, want: ErrClientMetadataJWKKeyIDMissing},
		{name: "two keys with the same kid", keys: []any{publicEncryptionJWK(t, "enc"), publicEncryptionJWK(t, "enc")}, want: ErrClientMetadataJWKKeyIDDuplicate},
	}
}

func clientMetadataWithKeys(keys []any) map[string]any {
	metadata := map[string]any{
		"vp_formats_supported": map[string]any{"dc+sd-jwt": map[string]any{}},
	}
	if keys != nil {
		metadata["jwks"] = map[string]any{"keys": keys}
	}
	return metadata
}

// A plain direct_post request from a redirect_uri Client Identifier carries
// its client_metadata as a query parameter, on both wire contracts. OpenID4VP
// 1.0 Section 5.1 requires the kid, so the 1.0 entry points refuse at parse
// with the typed sentinel inside an invalid_request unless the caller relaxed
// the rule with Experimental.AcceptClientMetadataJWKsWithoutKeyID. Draft 24 has no such rule.
func TestClientMetadataJWKKeyIDsOnPlainRequests(t *testing.T) {
	wires := []struct {
		name   string
		values func(responseURI string) url.Values
		parse  func(p *Oid4vpPresenter, uri string) (*CredentialPresentationRequest, error)
	}{
		{
			name: "Final",
			values: func(responseURI string) url.Values {
				return url.Values{
					"client_id":     {"redirect_uri:" + responseURI},
					"response_type": {"vp_token"},
					"response_mode": {"direct_post"},
					"response_uri":  {responseURI},
					"nonce":         {"n"},
					"dcql_query":    {finalDcqlParam},
				}
			},
			parse: (*Oid4vpPresenter).ParsePresentationRequest,
		},
		{
			name: "Draft24",
			values: func(responseURI string) url.Values {
				return draft24RedirectURIValues(responseURI, responseURI)
			},
			parse: parseDraft24ForTest,
		},
	}
	for _, wire := range wires {
		for _, keySet := range clientMetadataKeySets(t) {
			for _, relaxed := range []bool{false, true} {
				name := wire.name + "/" + keySet.name
				if relaxed {
					name += "/relaxed"
				} else {
					name += "/default"
				}
				required := !relaxed && wire.name == "Final"
				t.Run(name, func(t *testing.T) {
					verifier := newCountingResponseServer(t)
					responseURI := verifier.server.URL + "/response"
					values := wire.values(responseURI)
					encoded, err := json.Marshal(clientMetadataWithKeys(keySet.keys))
					require.NoError(t, err)
					values.Set("client_metadata", string(encoded))
					p := withExperimental(&Oid4vpPresenter{HTTPClient: verifier.server.Client()}, experimental.Presenter{
						Transport:                            experimental.Transport{AllowHTTP: true},
						AcceptClientMetadataJWKsWithoutKeyID: relaxed,
					})

					request, err := wire.parse(p, finalQueryURI(values))
					if !required || keySet.want == nil {
						require.NoError(t, err)
						require.NotNil(t, request.ClientMetadata)
						return
					}
					require.True(t, errors.Is(err, keySet.want), "want %v, got %v", keySet.want, err)
					assertAuthzErrorCode(t, err, InvalidRequestError)
					require.Equal(t, int32(0), verifier.calls.Load(), "a parse-time refusal must not be POSTed")
				})
			}
		}
	}
}

// A signed Request Object carries client_metadata as a claim. The by-value
// entry points of both wire contracts authenticate it through the same
// builder, so the requirement reaches it the same way.
func TestClientMetadataJWKKeyIDsOnSignedRequestObjects(t *testing.T) {
	f := newRequestObjectFixture(t, "verifier.example")
	withoutKeyID := func(draft24 bool) map[string]any {
		claims := f.claims()
		if draft24 {
			claims = f.draft24Claims()
		}
		metadata := claims["client_metadata"].(map[string]any)
		metadata["jwks"] = map[string]any{"keys": []any{publicEncryptionJWK(t, "")}}
		return claims
	}
	entryPoints := []struct {
		name    string
		draft24 bool
		parse   func(p *Oid4vpPresenter, requestObject string, clientID string) (*CredentialPresentationRequest, error)
	}{
		{name: "Final", parse: parseRequestObjectForTest},
		{name: "Draft24", draft24: true, parse: parseDraft24RequestObjectForTest},
	}
	for _, entry := range entryPoints {
		t.Run(entry.name, func(t *testing.T) {
			requestObject := f.sign(t, withoutKeyID(entry.draft24), nil)
			clientID := f.clientID()
			if entry.draft24 {
				clientID = draft24X509ClientID
			}

			relaxed := withExperimental(f.presenter(), experimental.Presenter{AcceptClientMetadataJWKsWithoutKeyID: true})
			request, err := entry.parse(relaxed, requestObject, clientID)
			require.NoError(t, err)
			require.NotNil(t, request.RequestObjectVerification)

			_, err = entry.parse(f.presenter(), requestObject, clientID)
			if entry.draft24 {
				// Draft 24 §5.1 does not require a kid.
				require.NoError(t, err)
			} else {
				require.True(t, errors.Is(err, ErrClientMetadataJWKKeyIDMissing), "want ErrClientMetadataJWKKeyIDMissing, got %v", err)
			}

			withKeyID := f.sign(t, f.claims(), nil)
			if entry.draft24 {
				withKeyID = f.sign(t, f.draft24Claims(), nil)
			}
			_, err = entry.parse(f.presenter(), withKeyID, clientID)
			require.NoError(t, err)
		})
	}
}

// The unsigned Digital Credentials API request is parsed by its own builder,
// which copies the same presenter policy.
func TestClientMetadataJWKKeyIDsOnDCAPIRequests(t *testing.T) {
	data := dcapiRaw(t, map[string]any{
		"response_type": "vp_token", "response_mode": "dc_api", "nonce": "n-1", "dcql_query": dcapiDCQL(),
		"client_metadata": clientMetadataWithKeys([]any{publicEncryptionJWK(t, "")}),
	})
	invocation := types.DCAPIInvocation{
		Request: types.DCAPIRequest{Protocol: DCAPIProtocolUnsigned, Data: data},
		Origin:  "https://verifier.example",
	}

	_, err := parseDCAPIForTest((&Oid4vpPresenter{}), invocation)
	require.True(t, errors.Is(err, ErrClientMetadataJWKKeyIDMissing), "want ErrClientMetadataJWKKeyIDMissing, got %v", err)

	_, err = parseDCAPIForTest(withExperimental(&Oid4vpPresenter{}, experimental.Presenter{AcceptClientMetadataJWKsWithoutKeyID: true}), invocation)
	require.NoError(t, err)
}
