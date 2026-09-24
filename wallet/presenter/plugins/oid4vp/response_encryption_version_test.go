package oid4vp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/url"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/profile"
)

// A Draft24 request is admitted without the HAIP rules even when the presenter
// enforces HAIP, so its response must be encrypted without them too: the HAIP
// constraints follow the protocol version of the request, not only the
// presenter's profile. Otherwise the request fails after consent.
func TestResponseEncryptionFollowsTheRequestVersion(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	metadata, err := json.Marshal(&VerifierMetadata{Jwks: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: &key.PublicKey, KeyID: "p384", Use: "enc", Algorithm: "ECDH-ES",
	}}}})
	require.NoError(t, err)
	uri := finalQueryURI(url.Values{
		"client_id":               {"redirect_uri:https://verifier.example/response"},
		"response_type":           {"vp_token"},
		"response_mode":           {"direct_post.jwt"},
		"response_uri":            {"https://verifier.example/response"},
		"nonce":                   {"n"},
		"client_metadata":         {string(metadata)},
		"presentation_definition": {`{"id":"definition"}`},
	})
	p := &Oid4vpPresenter{Profile: profile.HAIP}
	request, err := parseDraft24ForTest(p, uri)
	require.NoError(t, err, "Draft24 is admitted without the HAIP P-256 rule")

	_, err = encryptResponseForTest(p, map[string]any{"vp_token": "vp"}, request.ClientMetadata)
	require.NoError(t, err, "the response must be encrypted under the policy the request was admitted with")

	// Metadata the caller built itself carries no admission policy and is
	// encrypted under the presenter's profile.
	_, err = encryptResponseForTest(p, map[string]any{"vp_token": "vp"}, &VerifierMetadata{Jwks: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: &key.PublicKey, KeyID: "p384", Use: "enc", Algorithm: "ECDH-ES",
	}}}})
	require.ErrorIs(t, err, ErrResponseEncryptionKeyUnusable)
}
