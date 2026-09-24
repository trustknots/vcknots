package oid4vp

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/internal/testutil"
	"github.com/trustknots/vcknots/wallet/presenter/types"
	"github.com/trustknots/vcknots/wallet/profile"
)

func dcapiDCQL() map[string]any {
	return map[string]any{"credentials": []any{map[string]any{
		"id": "pid", "format": "dc+sd-jwt",
		"meta": map[string]any{"vct_values": []string{"urn:eudi:pid:1"}},
	}}}
}

func dcapiRaw(t *testing.T, value any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(value)
	require.NoError(t, err)
	return raw
}

func signedDCAPIClaims(f *requestObjectFixture) map[string]any {
	claims := f.claims()
	claims["response_mode"] = "dc_api.jwt"
	delete(claims, "response_uri")
	claims["expected_origins"] = []any{"https://verifier.example"}
	return claims
}

func TestParseDCAPIRequestUnsigned(t *testing.T) {
	p := &Oid4vpPresenter{}
	invocation := types.DCAPIInvocation{
		Request: types.DCAPIRequest{Protocol: DCAPIProtocolUnsigned, Data: dcapiRaw(t, map[string]any{
			"response_type": "vp_token", "response_mode": "dc_api", "nonce": "n-1", "dcql_query": dcapiDCQL(),
		})},
		Origin: "https://verifier.example",
	}
	request, err := parseDCAPIForTest(p, invocation)
	require.NoError(t, err)
	require.Equal(t, "web-origin:https://verifier.example", request.ClientID)
	require.Equal(t, "origin:https://verifier.example", request.ResponseAudience)
	require.Equal(t, DCAPIProtocolUnsigned, request.DCAPIProtocol)
}

func TestParseDCAPIRequestUnsignedIgnoresClientIDAndOrigins(t *testing.T) {
	// A.2: the Wallet MUST ignore client_id and expected_origins in unsigned
	// requests and use the platform Origin as the effective identifier.
	p := &Oid4vpPresenter{}
	invocation := types.DCAPIInvocation{
		Request: types.DCAPIRequest{Protocol: DCAPIProtocolUnsigned, Data: dcapiRaw(t, map[string]any{
			"client_id": "x509_hash:attacker", "expected_origins": []any{"https://attacker.example"},
			"response_type": "vp_token", "response_mode": "dc_api", "nonce": "n-1", "dcql_query": dcapiDCQL(),
		})},
		Origin: "https://verifier.example",
	}
	request, err := parseDCAPIForTest(p, invocation)
	require.NoError(t, err)
	require.Equal(t, "web-origin:https://verifier.example", request.ClientID)
}

func TestParseDCAPIRequestRejectsResponseURI(t *testing.T) {
	p := &Oid4vpPresenter{}
	invocation := types.DCAPIInvocation{
		Request: types.DCAPIRequest{Protocol: DCAPIProtocolUnsigned, Data: dcapiRaw(t, map[string]any{
			"response_type": "vp_token", "response_mode": "dc_api", "nonce": "n-1",
			"response_uri": "https://verifier.example/response", "dcql_query": dcapiDCQL(),
		})},
		Origin: "https://verifier.example",
	}
	_, err := parseDCAPIForTest(p, invocation)
	require.Error(t, err)
	require.Contains(t, err.Error(), "response_uri")
}

func TestParseDCAPIRequestSigned(t *testing.T) {
	f := newRequestObjectFixture(t)
	obj := f.sign(t, signedDCAPIClaims(f), nil)
	invocation := types.DCAPIInvocation{
		Request: types.DCAPIRequest{Protocol: DCAPIProtocolSigned, Data: dcapiRaw(t, map[string]any{"request": obj})},
		Origin:  "https://verifier.example",
	}
	request, err := parseDCAPIForTest(f.presenter(), invocation)
	require.NoError(t, err)
	require.Equal(t, f.clientID(), request.ClientID)
	require.Equal(t, "origin:https://verifier.example", request.ResponseAudience)
	require.NotNil(t, request.RequestObjectVerification)
	require.Equal(t, f.clientID(), request.RequestObjectVerification.ClientID)
}

func TestParseDCAPIRequestSignedWrongExpectedOrigins(t *testing.T) {
	f := newRequestObjectFixture(t)
	claims := signedDCAPIClaims(f)
	claims["expected_origins"] = []any{"https://attacker.example"}
	obj := f.sign(t, claims, nil)
	invocation := types.DCAPIInvocation{
		Request: types.DCAPIRequest{Protocol: DCAPIProtocolSigned, Data: dcapiRaw(t, map[string]any{"request": obj})},
		Origin:  "https://verifier.example",
	}
	_, err := parseDCAPIForTest(f.presenter(), invocation)
	require.Error(t, err)
	require.Contains(t, err.Error(), "expected_origins")
}

func TestParseDCAPIRequestOriginComesFromInvocation(t *testing.T) {
	// The request names a different origin in expected_origins; the platform
	// Origin supplied by the invocation must be the one compared.
	f := newRequestObjectFixture(t)
	claims := signedDCAPIClaims(f)
	claims["expected_origins"] = []any{"https://verifier.example"}
	obj := f.sign(t, claims, nil)
	invocation := types.DCAPIInvocation{
		Request: types.DCAPIRequest{Protocol: DCAPIProtocolSigned, Data: dcapiRaw(t, map[string]any{"request": obj})},
		Origin:  "https://attacker.example",
	}
	_, err := parseDCAPIForTest(f.presenter(), invocation)
	require.Error(t, err)
	require.Contains(t, err.Error(), "expected_origins")
}

func signDCAPIMultiPart(t *testing.T, key *ecdsa.PrivateKey, leaf *x509.Certificate, clientID string, payload []byte) string {
	t.Helper()
	options := (&jose.SignerOptions{}).
		WithType("oauth-authz-req+jwt").
		WithHeader("x5c", []string{base64.StdEncoding.EncodeToString(leaf.Raw)}).
		WithHeader("client_id", clientID)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, options)
	require.NoError(t, err)
	obj, err := signer.Sign(payload)
	require.NoError(t, err)
	compact, err := obj.CompactSerialize()
	require.NoError(t, err)
	return compact
}

func TestParseDCAPIRequestMultiSigned(t *testing.T) {
	trusted := newRequestObjectFixture(t)
	untrusted := newRequestObjectFixture(t)
	claims := signedDCAPIClaims(trusted)
	delete(claims, "client_id")
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	trustedCompact := signDCAPIMultiPart(t, trusted.key, trusted.leaf, trusted.clientID(), payload)
	untrustedCompact := signDCAPIMultiPart(t, untrusted.key, untrusted.leaf, untrusted.clientID(), payload)
	trustedParts := strings.Split(trustedCompact, ".")
	untrustedParts := strings.Split(untrustedCompact, ".")
	require.Len(t, trustedParts, 3)
	require.Len(t, untrustedParts, 3)
	multi := map[string]any{
		"payload": trustedParts[1],
		"signatures": []any{
			map[string]any{"protected": untrustedParts[0], "signature": untrustedParts[2]},
			map[string]any{"protected": trustedParts[0], "signature": trustedParts[2]},
		},
	}
	invocation := types.DCAPIInvocation{
		Request: types.DCAPIRequest{Protocol: DCAPIProtocolMultiSigned, Data: dcapiRaw(t, map[string]any{"request": multi})},
		Origin:  "https://verifier.example",
	}
	request, err := parseDCAPIForTest(trusted.presenter(), invocation)
	require.NoError(t, err)
	require.Equal(t, trusted.clientID(), request.ClientID)
	require.Equal(t, "origin:https://verifier.example", request.ResponseAudience)
	require.NotNil(t, request.RequestObjectVerification)
	require.Equal(t, trusted.clientID(), request.RequestObjectVerification.ClientID)
}

func dcapiUnsignedDataWithMetadata(t *testing.T, recipient *ecdsa.PrivateKey, encValues []string) []byte {
	t.Helper()
	metadata := map[string]any{
		"jwks": jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: &recipient.PublicKey, KeyID: "enc-key", Use: "enc", Algorithm: "ECDH-ES",
		}}},
		"encrypted_response_enc_values_supported": encValues,
	}
	return dcapiRaw(t, map[string]any{
		"response_type": "vp_token", "response_mode": "dc_api.jwt", "nonce": "n-1",
		"dcql_query": dcapiDCQL(), "client_metadata": metadata,
	})
}

func TestSubmitDCQLResponseDCAPIPlaintext(t *testing.T) {
	p := &Oid4vpPresenter{}
	request, err := p.ParseDCAPIRequest(context.Background(), dcapiUnsignedInvocation(t, "dc_api"))
	require.NoError(t, err)
	vpToken := map[string][]string{"pid": {"credential"}}
	result, err := p.SubmitDCQLResponse(context.Background(), request, vpToken)
	require.NoError(t, err)
	require.False(t, result.Encrypted)
	require.Equal(t, DCAPIProtocolUnsigned, result.DCAPIResponse.Protocol)
	require.Equal(t, vpToken, result.DCAPIResponse.Data["vp_token"])
}

func TestSubmitDCQLResponseDCAPIEncrypted(t *testing.T) {
	for _, tc := range []struct {
		name      string
		profile   profile.Profile
		encValues []string
		enc       jose.ContentEncryption
	}{
		{name: "final defaults to A128GCM", enc: jose.A128GCM},
		{name: "haip prefers A256GCM", profile: profile.HAIP, encValues: []string{"A128GCM", "A256GCM"}, enc: jose.A256GCM},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recipient := testutil.NewP256Key(t)
			p := &Oid4vpPresenter{Profile: tc.profile}
			invocation := types.DCAPIInvocation{
				Request: types.DCAPIRequest{Protocol: DCAPIProtocolUnsigned, Data: dcapiUnsignedDataWithMetadata(t, recipient, tc.encValues)},
				Origin:  "https://verifier.example",
			}
			request, err := p.ParseDCAPIRequest(context.Background(), invocation)
			require.NoError(t, err)
			result, err := p.SubmitDCQLResponse(context.Background(), request, map[string][]string{"pid": {"credential"}})
			require.NoError(t, err)
			require.True(t, result.Encrypted)
			response := result.DCAPIResponse
			require.Equal(t, DCAPIProtocolUnsigned, response.Protocol)
			token, ok := response.Data["response"].(string)
			require.True(t, ok)
			jwe, err := jose.ParseEncrypted(token, []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{tc.enc})
			require.NoError(t, err)
			plaintext, err := jwe.Decrypt(recipient)
			require.NoError(t, err)
			var payload map[string]any
			require.NoError(t, json.Unmarshal(plaintext, &payload))
			vpToken, ok := payload["vp_token"].(map[string]any)
			require.True(t, ok)
			require.Equal(t, []any{"credential"}, vpToken["pid"])
		})
	}
}

func TestParseDCAPIRequestHAIPAcceptsAllRequestTypes(t *testing.T) {
	t.Run("unsigned", func(t *testing.T) {
		p := &Oid4vpPresenter{Profile: profile.HAIP}
		invocation := types.DCAPIInvocation{
			Request: types.DCAPIRequest{Protocol: DCAPIProtocolUnsigned, Data: dcapiUnsignedDataWithMetadata(t, testutil.NewP256Key(t), []string{"A128GCM", "A256GCM"})},
			Origin:  "https://verifier.example",
		}
		_, err := parseDCAPIForTest(p, invocation)
		require.NoError(t, err)
	})

	t.Run("signed", func(t *testing.T) {
		f := newRequestObjectFixture(t)
		obj := f.sign(t, signedDCAPIClaims(f), nil)
		invocation := types.DCAPIInvocation{
			Request: types.DCAPIRequest{Protocol: DCAPIProtocolSigned, Data: dcapiRaw(t, map[string]any{"request": obj})},
			Origin:  "https://verifier.example",
		}
		p := f.presenterWithHAIP()
		_, err := parseDCAPIForTest(p, invocation)
		require.NoError(t, err)
	})

	t.Run("multi-signed", func(t *testing.T) {
		trusted := newRequestObjectFixture(t)
		untrusted := newRequestObjectFixture(t)
		claims := signedDCAPIClaims(trusted)
		delete(claims, "client_id")
		payload, err := json.Marshal(claims)
		require.NoError(t, err)
		trustedCompact := signDCAPIMultiPart(t, trusted.key, trusted.leaf, trusted.clientID(), payload)
		untrustedCompact := signDCAPIMultiPart(t, untrusted.key, untrusted.leaf, untrusted.clientID(), payload)
		trustedParts := strings.Split(trustedCompact, ".")
		untrustedParts := strings.Split(untrustedCompact, ".")
		multi := map[string]any{
			"payload": trustedParts[1],
			"signatures": []any{
				map[string]any{"protected": untrustedParts[0], "signature": untrustedParts[2]},
				map[string]any{"protected": trustedParts[0], "signature": trustedParts[2]},
			},
		}
		invocation := types.DCAPIInvocation{
			Request: types.DCAPIRequest{Protocol: DCAPIProtocolMultiSigned, Data: dcapiRaw(t, map[string]any{"request": multi})},
			Origin:  "https://verifier.example",
		}
		p := trusted.presenterWithHAIP()
		_, err = parseDCAPIForTest(p, invocation)
		require.NoError(t, err)
	})
}

func TestParseDCAPIRequestHAIPRejectsDirectPost(t *testing.T) {
	p := (&Oid4vpPresenter{Profile: profile.HAIP})
	invocation := types.DCAPIInvocation{
		Request: types.DCAPIRequest{Protocol: DCAPIProtocolUnsigned, Data: dcapiRaw(t, map[string]any{
			"response_type": "vp_token", "response_mode": "direct_post.jwt", "nonce": "n-1", "dcql_query": dcapiDCQL(),
		})},
		Origin: "https://verifier.example",
	}
	_, err := parseDCAPIForTest(p, invocation)
	require.Error(t, err)
}

// TestHAIPDCAPIRejectsAnchorInX5CWithRootCAs covers HAIP Section 5 on the DC
// API path: "The X.509 certificate of the trust anchor MUST NOT be included in
// the x5c JOSE header of the signed request." It holds when trust is
// configured as a *x509.CertPool instead of explicit TrustAnchors.
func TestHAIPDCAPIRejectsAnchorInX5CWithRootCAs(t *testing.T) {
	f := newRequestObjectFixture(t)
	pool := x509.NewCertPool()
	pool.AddCert(f.root)
	options := RequestObjectValidationOptions{RootCAs: pool, Now: func() time.Time { return f.now }}
	invocation := types.DCAPIInvocation{
		Request: types.DCAPIRequest{Protocol: DCAPIProtocolSigned, Data: dcapiRaw(t, map[string]any{
			"request": f.signWithRoot(t, signedDCAPIClaims(f), true),
		})},
		Origin: "https://verifier.example",
	}

	haip := &Oid4vpPresenter{HTTPClient: f.server.Client(), RequestObjectValidation: &options, Profile: profile.HAIP}
	_, err := parseDCAPIForTest(haip, invocation)
	require.ErrorContains(t, err, "HAIP forbids including the trust anchor certificate in the x5c header")

	final := &Oid4vpPresenter{HTTPClient: f.server.Client(), RequestObjectValidation: &options}
	_, err = parseDCAPIForTest(final, invocation)
	require.NoError(t, err, "Final must still accept a chain that includes the anchor")
}

// presenterWithHAIP mirrors requestObjectFixture.presenterWith for the HAIP
// profile without changing the shared fixture file.
func (f *requestObjectFixture) presenterWithHAIP() *Oid4vpPresenter {
	return f.presenterWith(requestFixtureOptions{Profile: profile.HAIP})
}

// TestParseRequestRejectsWebOriginClientIDFromTheWire pins that "web-origin" is
// an identifier the Wallet mints for itself, not one a Verifier may claim.
//
// OID4VP 1.0 Appendix A.2: "The `client_id` parameter MUST be omitted in
// unsigned requests defined in (#unsigned_request). The Wallet MUST ignore any
// `client_id` parameter that is present in an unsigned request." Accepting the
// prefix off the wire would reintroduce, under a different spelling, what
// Section 5.9.3 forbids for the companion prefix: "This reserved Client
// Identifier Prefix is defined in (#dc_api_request). The Wallet MUST NOT accept
// this Client Identifier Prefix in requests." Such a request derives no
// response endpoint binding from its Client Identifier, so a direct_post.jwt
// response_uri would be unauthenticated.
func TestParseRequestRejectsWebOriginClientIDFromTheWire(t *testing.T) {
	const webOriginClientID = "web-origin:https://verifier.example"

	t.Run("query parameters", func(t *testing.T) {
		p := &Oid4vpPresenter{}
		uri := "openid4vp://present?" + url.Values{
			"client_id":     {webOriginClientID},
			"response_type": {"vp_token"},
			"nonce":         {"n-1"},
			"response_mode": {"direct_post.jwt"},
			"response_uri":  {"https://attacker.example/cb"},
			"dcql_query":    {string(dcapiRaw(t, dcapiDCQL()))},
		}.Encode()
		_, err := p.ParsePresentationRequest(uri)
		require.Error(t, err)
		require.Contains(t, err.Error(), "web-origin")
	})

	t.Run("signed Request Object by value with an outer client_id", func(t *testing.T) {
		f := newRequestObjectFixture(t)
		claims := f.claims()
		claims["client_id"] = webOriginClientID
		uri := "openid4vp://authorize?" + url.Values{
			"client_id": {webOriginClientID},
			"request":   {f.sign(t, claims, nil)},
		}.Encode()
		_, err := f.presenter().ParsePresentationRequest(uri)
		require.Error(t, err)
		require.Contains(t, err.Error(), "web-origin")
	})

	t.Run("signed Request Object by reference", func(t *testing.T) {
		f := newRequestObjectFixture(t)
		claims := f.claims()
		claims["client_id"] = webOriginClientID
		f.requestObject = []byte(f.sign(t, claims, nil))
		uri := "openid4vp://authorize?" + url.Values{
			"client_id":   {webOriginClientID},
			"request_uri": {f.server.URL + "/request-object"},
		}.Encode()
		_, err := f.presenter().ParsePresentationRequest(uri)
		require.Error(t, err)
		require.Contains(t, err.Error(), "web-origin")
	})

	t.Run("Draft24 query parameters", func(t *testing.T) {
		p := &Oid4vpPresenter{}
		uri := "openid4vp://present?" + url.Values{
			"client_id":               {webOriginClientID},
			"response_type":           {"vp_token"},
			"nonce":                   {"n-1"},
			"response_mode":           {"direct_post"},
			"response_uri":            {"https://attacker.example/cb"},
			"presentation_definition": {`{"id":"pd","input_descriptors":[]}`},
		}.Encode()
		_, err := parseDraft24ForTest(p, uri)
		require.Error(t, err)
		require.Contains(t, err.Error(), "web-origin")
	})

	t.Run("Draft24 Request Object claim", func(t *testing.T) {
		// Draft24 accepts a Request Object without an outer client_id, so the
		// rejection here comes from the parameter assembly that reads the
		// Request Object's own client_id claim, not from the early outer check.
		f := newRequestObjectFixture(t)
		claims := f.claims()
		claims["client_id"] = webOriginClientID
		claims["response_mode"] = "direct_post"
		claims["response_uri"] = "https://attacker.example/cb"
		uri := "openid4vp://authorize?" + url.Values{"request": {f.sign(t, claims, nil)}}.Encode()
		_, err := parseDraft24ForTest(f.presenter(), uri)
		require.Error(t, err)
		require.Contains(t, err.Error(), "web-origin")
	})
}

// TestParseDCAPIRequestRequestObjectSentinels drives the DC API Request Object
// authentication sentinels through ParseDCAPIRequest, so each is proven
// reachable with errors.Is from the innermost return in dcapi.go rather than
// through a message-fragment classification.
func TestParseDCAPIRequestRequestObjectSentinels(t *testing.T) {
	tests := []struct {
		name     string
		sentinel error
		object   func(*testing.T, *requestObjectFixture) string
	}{
		{
			name:     "typ invalid",
			sentinel: ErrRequestObjectTypInvalid,
			object: func(t *testing.T, f *requestObjectFixture) string {
				options := (&jose.SignerOptions{}).
					WithType("JWT").
					WithHeader("x5c", []string{base64.StdEncoding.EncodeToString(f.leaf.Raw)})
				return f.sign(t, signedDCAPIClaims(f), options)
			},
		},
		{
			name:     "signature invalid",
			sentinel: ErrRequestObjectSignatureInvalid,
			object: func(t *testing.T, f *requestObjectFixture) string {
				// Present f's certificate in x5c so the client_id binding
				// passes, but sign with another key so verification fails.
				other := newRequestObjectFixture(t)
				options := (&jose.SignerOptions{}).
					WithType("oauth-authz-req+jwt").
					WithHeader("x5c", []string{base64.StdEncoding.EncodeToString(f.leaf.Raw)})
				signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: other.key}, options)
				require.NoError(t, err)
				token, err := jwt.Signed(signer).Claims(signedDCAPIClaims(f)).Serialize()
				require.NoError(t, err)
				return token
			},
		},
		{
			name:     "audience mismatch",
			sentinel: ErrRequestObjectAudienceMismatch,
			object: func(t *testing.T, f *requestObjectFixture) string {
				claims := signedDCAPIClaims(f)
				claims["aud"] = "another-wallet"
				return f.sign(t, claims, nil)
			},
		},
		{
			name:     "expired",
			sentinel: ErrRequestObjectExpired,
			object: func(t *testing.T, f *requestObjectFixture) string {
				claims := signedDCAPIClaims(f)
				claims["exp"] = f.now.Add(-time.Second).Unix()
				return f.sign(t, claims, nil)
			},
		},
		{
			name:     "x509_hash mismatch",
			sentinel: ErrX509HashMismatch,
			object: func(t *testing.T, f *requestObjectFixture) string {
				claims := signedDCAPIClaims(f)
				claims["client_id"] = "x509_hash:" + base64.RawURLEncoding.EncodeToString([]byte("wrong-leaf-hash"))
				return f.sign(t, claims, nil)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newRequestObjectFixture(t)
			invocation := types.DCAPIInvocation{
				Request: types.DCAPIRequest{Protocol: DCAPIProtocolSigned, Data: dcapiRaw(t, map[string]any{"request": tt.object(t, f)})},
				Origin:  "https://verifier.example",
			}
			_, err := parseDCAPIForTest(f.presenter(), invocation)
			if !errors.Is(err, tt.sentinel) {
				t.Fatalf("ParseDCAPIRequest did not return %v: %v", tt.sentinel, err)
			}
		})
	}
}

// A DC API request is admitted through the same final checks as every other
// delivery: the response mode must be a DC API mode (OID4VP 1.0 Appendix A.2),
// and a dc_api.jwt request must leave the Wallet a key to encrypt to.
func TestParseDCAPIRequestAdmission(t *testing.T) {
	unsigned := func(data map[string]any) types.DCAPIInvocation {
		return types.DCAPIInvocation{
			Request: types.DCAPIRequest{Protocol: DCAPIProtocolUnsigned, Data: dcapiRaw(t, data)},
			Origin:  "https://verifier.example",
		}
	}
	base := func(mode string) map[string]any {
		return map[string]any{"response_type": "vp_token", "response_mode": mode, "nonce": "n-1", "dcql_query": dcapiDCQL()}
	}

	t.Run("non-DC API response mode", func(t *testing.T) {
		for _, mode := range []string{"direct_post", "fragment"} {
			data := base(mode)
			data["redirect_uri"] = "https://verifier.example/cb"
			_, err := parseDCAPIForTest((&Oid4vpPresenter{}), unsigned(data))
			assertAuthzErrorCode(t, err, InvalidRequestError)
		}
	})

	t.Run("dc_api.jwt without an encryption key", func(t *testing.T) {
		_, err := parseDCAPIForTest((&Oid4vpPresenter{}), unsigned(base("dc_api.jwt")))
		require.ErrorIs(t, err, ErrResponseEncryptionKeyMissing)
	})

	t.Run("HAIP requires both content encryptions on dc_api.jwt too", func(t *testing.T) {
		recipient := testutil.NewP256Key(t)
		invocation := types.DCAPIInvocation{
			Request: types.DCAPIRequest{Protocol: DCAPIProtocolUnsigned, Data: dcapiUnsignedDataWithMetadata(t, recipient, []string{"A256GCM"})},
			Origin:  "https://verifier.example",
		}
		_, err := parseDCAPIForTest((&Oid4vpPresenter{Profile: profile.HAIP}), invocation)
		require.ErrorIs(t, err, ErrResponseEncryptionEncMissing)
	})
}

// dc_api and dc_api.jwt are DC API response modes; another delivery cannot
// use them.
func TestDCAPIResponseModeRefusedOutsideTheDCAPI(t *testing.T) {
	f := newRequestObjectFixture(t)
	claims := f.claims()
	claims["response_mode"] = "dc_api"
	delete(claims, "response_uri")
	_, err := f.parseRequest(t, claims, requestFixtureOptions{Delivery: deliverByReference})
	assertAuthzErrorCode(t, err, InvalidRequestError)
}
