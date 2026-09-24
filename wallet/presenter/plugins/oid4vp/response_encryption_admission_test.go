package oid4vp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/url"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/profile"
)

// encryptionMetadataWith is responseEncryptionMetadata with its jwks and
// encrypted_response_enc_values_supported replaced.
func encryptionMetadataWith(keys []jose.JSONWebKey, encValues []string) *VerifierMetadata {
	metadata := responseEncryptionMetadata()
	metadata.Jwks = jose.JSONWebKeySet{Keys: keys}
	metadata.EncryptedResponseEncValuesSupported = encValues
	return metadata
}

func metadataClaim(t *testing.T, metadata *VerifierMetadata) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(metadata)
	require.NoError(t, err)
	var claim map[string]any
	require.NoError(t, json.Unmarshal(encoded, &claim))
	return claim
}

// A direct_post.jwt request whose Verifier metadata leaves nothing to encrypt
// the Authorization Response to is refused while it is parsed, before the
// holder is asked to consent, and the refusal is never answered to the
// Verifier: it asked for an encrypted response, so not even an error goes out
// in the clear.
func TestDirectPostJWTRefusedAtParseWithoutUsableEncryption(t *testing.T) {
	p256 := fixtureResponseEncryptionKey()
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	usable := jose.JSONWebKey{Key: &p256.PublicKey, KeyID: "enc", Use: "enc", Algorithm: "ECDH-ES"}

	tests := []struct {
		name     string
		metadata *VerifierMetadata
		want     error
	}{
		{name: "no client_metadata", want: ErrResponseEncryptionKeyMissing},
		{name: "empty jwks", metadata: encryptionMetadataWith(nil, []string{"A128GCM"}), want: ErrResponseEncryptionKeyMissing},
		{name: "signing key only", metadata: encryptionMetadataWith([]jose.JSONWebKey{{Key: &p256.PublicKey, Use: "sig", Algorithm: "ECDH-ES"}}, nil), want: ErrResponseEncryptionKeyUnusable},
		{name: "RSA key", metadata: encryptionMetadataWith([]jose.JSONWebKey{{Key: &rsaKey.PublicKey, Use: "enc", Algorithm: "RSA-OAEP-256"}}, nil), want: ErrResponseEncryptionKeyUnusable},
		{name: "key without alg", metadata: encryptionMetadataWith([]jose.JSONWebKey{{Key: &p256.PublicKey, Use: "enc"}}, nil), want: ErrResponseEncryptionKeyUnusable},
		{name: "no supported enc", metadata: encryptionMetadataWith([]jose.JSONWebKey{usable}, []string{"XC20P"}), want: ErrResponseEncryptionEncUnsupported},
		{name: "P-384 key is usable under Final", metadata: encryptionMetadataWith([]jose.JSONWebKey{{Key: &p384.PublicKey, Use: "enc", Algorithm: "ECDH-ES"}}, nil)},
		{name: "A128GCM alone is enough under Final", metadata: encryptionMetadataWith([]jose.JSONWebKey{usable}, []string{"A128GCM"})},
		{name: "absent enc list defaults to A128GCM", metadata: encryptionMetadataWith([]jose.JSONWebKey{usable}, nil)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier := newCountingResponseServer(t)
			responseURI := verifier.server.URL + "/response"
			values := url.Values{
				"client_id":     {"redirect_uri:" + responseURI},
				"response_type": {"vp_token"},
				"response_mode": {"direct_post.jwt"},
				"response_uri":  {responseURI},
				"nonce":         {"n"},
				"dcql_query":    {finalDcqlParam},
			}
			if tt.metadata != nil {
				encoded, err := json.Marshal(tt.metadata)
				require.NoError(t, err)
				values.Set("client_metadata", string(encoded))
			}
			p := &Oid4vpPresenter{AllowHTTP: true, HTTPClient: verifier.server.Client()}
			req, err := p.ParsePresentationRequest(finalQueryURI(values))
			if tt.want == nil {
				require.NoError(t, err)
				require.Equal(t, OAuthAuthzReqResponseModeDirectPostJWT, req.ResponseMode)
				return
			}
			require.True(t, errors.Is(err, tt.want), "want %v, got %v", tt.want, err)
			assertAuthzErrorCode(t, err, InvalidRequestError)
			require.Equal(t, int32(0), verifier.calls.Load(), "a response encryption refusal must not be POSTed")
		})
	}
}

// The same refusal applies on the Draft24 wire contract: the response of a
// Draft24 direct_post.jwt request is encrypted with the same selection.
func TestDraft24DirectPostJWTRefusedAtParseWithoutEncryptionKey(t *testing.T) {
	verifier := newCountingResponseServer(t)
	responseURI := verifier.server.URL + "/response"
	values := draft24RedirectURIValues(responseURI, responseURI)
	values.Set("response_mode", "direct_post.jwt")
	p := &Oid4vpPresenter{AllowHTTP: true, HTTPClient: verifier.server.Client()}
	_, err := parseDraft24ForTest(p, finalQueryURI(values))
	require.True(t, errors.Is(err, ErrResponseEncryptionKeyMissing), "want ErrResponseEncryptionKeyMissing, got %v", err)
	require.Equal(t, int32(0), verifier.calls.Load(), "a response encryption refusal must not be POSTed")

	values.Set("client_metadata", responseEncryptionClientMetadataParam())
	_, err = parseDraft24ForTest(p, finalQueryURI(values))
	require.NoError(t, err)
}

// HAIP Section 5 narrows the selection to a P-256 ECDH-ES key with A128GCM or
// A256GCM, and requires every Verifier using response encryption to list both.
// Draft24 is exempt from the HAIP rules, as it is from every HAIP checkpoint.
func TestHAIPDirectPostJWTEncryptionAdmission(t *testing.T) {
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	usable := responseEncryptionMetadata().Jwks.Keys[0]

	tests := []struct {
		name     string
		metadata *VerifierMetadata
		want     error
	}{
		{name: "both GCM values", metadata: responseEncryptionMetadata()},
		{name: "A128GCM only", metadata: encryptionMetadataWith([]jose.JSONWebKey{usable}, []string{"A128GCM"}), want: ErrResponseEncryptionEncMissing},
		{name: "A256GCM only", metadata: encryptionMetadataWith([]jose.JSONWebKey{usable}, []string{"A256GCM"}), want: ErrResponseEncryptionEncMissing},
		{name: "enc list absent", metadata: encryptionMetadataWith([]jose.JSONWebKey{usable}, nil), want: ErrResponseEncryptionEncMissing},
		{name: "only CBC values", metadata: encryptionMetadataWith([]jose.JSONWebKey{usable}, []string{"A256CBC-HS512"}), want: ErrResponseEncryptionEncUnsupported},
		{name: "P-384 key", metadata: encryptionMetadataWith([]jose.JSONWebKey{{Key: &p384.PublicKey, Use: "enc", Algorithm: "ECDH-ES"}}, []string{"A128GCM", "A256GCM"}), want: ErrResponseEncryptionKeyUnusable},
		{name: "key wrapping alg", metadata: encryptionMetadataWith([]jose.JSONWebKey{{Key: usable.Key, Use: "enc", Algorithm: "ECDH-ES+A128KW"}}, []string{"A128GCM", "A256GCM"}), want: ErrResponseEncryptionKeyUnusable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newRequestObjectFixture(t)
			claims := f.claims()
			claims["client_metadata"] = metadataClaim(t, tt.metadata)
			_, err := f.parseRequest(t, claims, requestFixtureOptions{Profile: profile.HAIP, Delivery: deliverByReference})
			if tt.want == nil {
				require.NoError(t, err)
				return
			}
			require.True(t, errors.Is(err, tt.want), "want %v, got %v", tt.want, err)
		})
	}

	t.Run("Draft24 is exempt from the HAIP enc rule", func(t *testing.T) {
		f := newRequestObjectFixture(t)
		claims := f.claims()
		claims["client_metadata"] = metadataClaim(t, encryptionMetadataWith([]jose.JSONWebKey{usable}, []string{"A128GCM"}))
		uri := "openid4vp://authorize?" + url.Values{"client_id": {f.clientID()}, "request": {f.sign(t, claims, nil)}}.Encode()
		p := f.presenter()
		p.Profile = profile.HAIP
		_, err := parseDraft24ForTest(p, uri)
		require.NoError(t, err)
	})
}
