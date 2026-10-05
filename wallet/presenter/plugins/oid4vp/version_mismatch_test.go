package oid4vp

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustknots/vcknots/wallet/presenter/types"
	"github.com/trustknots/vcknots/wallet/profile"
)

// countingDraft24Handler serves claims at /request-object, echoing a POSTed
// wallet_nonce, and counts the fetches.
func (f *requestObjectFixture) countingDraft24Handler(t *testing.T, claims map[string]any) *atomic.Int32 {
	fetches := &atomic.Int32{}
	f.setRequestObjectHandler(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		_ = r.ParseForm()
		signed := map[string]any{}
		for name, value := range claims {
			signed[name] = value
		}
		if nonce := r.Form.Get("wallet_nonce"); nonce != "" {
			signed["wallet_nonce"] = nonce
		}
		w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
		_, _ = w.Write([]byte(f.sign(t, signed, nil)))
	})
	return fetches
}

// The outer request says response_mode=direct_post.jwt, which a
// router reads as OpenID4VP 1.0, but the signed Request Object behind
// request_uri carries a Presentation Exchange definition: a Draft 24 request
// with an encrypted response (Draft 24 §8.3.1). The OpenID4VP 1.0 entry point
// names the version, and the Draft 24 re-admission authenticates the same
// Request Object without fetching request_uri again - including the
// wallet_nonce of a request_uri POST (Draft 24 §5.11).
func TestFinalEntryPointHandsAPresentationExchangeRequestToDraft24(t *testing.T) {
	for _, post := range []bool{false, true} {
		name := "get"
		if post {
			name = "post"
		}
		t.Run(name, func(t *testing.T) {
			f := newRequestObjectFixture(t, "verifier.example")
			claims := f.draft24Claims()
			claims["response_mode"] = "direct_post.jwt"
			claims["presentation_definition"] = map[string]any{"id": "pid-definition", "input_descriptors": []any{map[string]any{"id": "pid"}}}
			fetches := f.countingDraft24Handler(t, claims)
			p := f.presenter()
			values := url.Values{
				"client_id":     {draft24X509ClientID},
				"response_mode": {"direct_post.jwt"},
				"request_uri":   {f.server.URL + "/request-object"},
			}
			if post {
				values.Set("request_uri_method", "post")
			}

			_, err := p.ParseRequest(context.Background(), "openid4vp://authorize?"+values.Encode())
			require.ErrorIs(t, err, ErrProtocolVersionMismatch)
			var mismatch *VersionMismatchError
			require.ErrorAs(t, err, &mismatch)
			require.Equal(t, profile.VersionDraft24, mismatch.Version)
			require.Equal(t, "presentation_definition", mismatch.Parameter)
			require.EqualValues(t, 1, fetches.Load())

			admitted, err := p.AdmitUnderVersion(context.Background(), err)
			require.NoError(t, err)
			handle := admitted.(*AdmittedRequest)
			require.True(t, handle.Draft24())
			require.EqualValues(t, 1, fetches.Load(), "the Request Object is not fetched again")
			request := handle.Request()
			require.Equal(t, "pid-definition", request.PresentationDefinition.ID)
			require.Equal(t, "reference", request.RequestObjectVerification.Delivery)
			if post {
				require.NotEmpty(t, request.RequestObjectVerification.WalletNonce)
			}
			// Delivered by reference, the re-admitted request can be sealed and
			// answered in a later call.
			sealed, err := handle.Seal(sealKey)
			require.NoError(t, err)
			_, err = p.ReadmitDraft24Request(context.Background(), sealed, sealKey)
			require.NoError(t, err)
		})
	}
}

// The re-admission authenticates the Request Object under every Draft 24
// rule: a Request Object whose POST did not echo the wallet_nonce is refused
// there as well (Draft 24 §5.11.1).
func TestAdmitUnderVersionAuthenticatesTheRequestObjectAgain(t *testing.T) {
	f := newRequestObjectFixture(t, "verifier.example")
	claims := f.draft24Claims()
	claims["wallet_nonce"] = "not-the-one-sent"
	f.publish(t, claims)
	p := f.presenter()
	_, err := p.ParseRequest(context.Background(), f.referenceURI(draft24X509ClientID, true))
	require.ErrorIs(t, err, ErrProtocolVersionMismatch)
	_, err = p.AdmitUnderVersion(context.Background(), err)
	require.ErrorIs(t, err, ErrRequestObjectWalletNonceMismatch)
}

// The version is decided before any rule only OpenID4VP 1.0 has: a Draft 24
// request whose client_metadata.jwks carries no kid (which OpenID4VP 1.0 §5.1
// requires and Draft 24 does not) is named a Draft 24 request, not refused as
// an invalid 1.0 one.
func TestVersionDecisionPrecedesFinalOnlyRules(t *testing.T) {
	metadata := `{"jwks":{"keys":[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","use":"enc","alg":"ECDH-ES"}]},"vp_formats":{"vc+sd-jwt":{}}}`
	params := url.Values{
		"client_id":               {"redirect_uri:https://verifier.example/response"},
		"response_type":           {"vp_token"},
		"response_mode":           {"direct_post"},
		"nonce":                   {"n"},
		"client_metadata":         {metadata},
		"presentation_definition": {`{"id":"pd","input_descriptors":[{"id":"pid"}]}`},
	}
	p := &Oid4vpPresenter{}
	_, err := p.ParseRequest(context.Background(), "openid4vp://present?"+params.Encode())
	require.ErrorIs(t, err, ErrProtocolVersionMismatch)
	admitted, err := p.AdmitUnderVersion(context.Background(), err)
	require.NoError(t, err)
	require.Equal(t, "https://verifier.example/response", admitted.(*AdmittedRequest).ResponseEndpoint().String())

	// The same request with dcql_query instead is a 1.0 request, and the kid
	// rule applies.
	params.Del("presentation_definition")
	params.Set("dcql_query", `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:x"]}}]}`)
	_, err = p.ParseRequest(context.Background(), "openid4vp://present?"+params.Encode())
	require.ErrorIs(t, err, ErrClientMetadataJWKKeyIDMissing)
}

// OpenID4VP 1.0 §5: "The Wallet MUST ignore any unrecognized parameters". A
// request with dcql_query is a 1.0 request even when it also carries
// Presentation Exchange parameters.
func TestFinalIgnoresPresentationExchangeBesideDCQL(t *testing.T) {
	f := newRequestObjectFixture(t)
	claims := f.claims()
	claims["presentation_definition"] = map[string]any{"id": "ignored"}
	request, err := f.parse(t, claims)
	require.NoError(t, err)
	require.Nil(t, request.PresentationDefinition)
	require.NotNil(t, request.DcqlQuery)
}

// AdmitUnderVersion acts only on a refusal its own presenter produced.
func TestAdmitUnderVersionRefusesForeignErrors(t *testing.T) {
	params := url.Values{
		"client_id":     {"redirect_uri:https://verifier.example/response"},
		"response_type": {"vp_token"}, "response_mode": {"direct_post"}, "nonce": {"n"},
		"presentation_definition": {`{"id":"pd","input_descriptors":[{"id":"pid"}]}`},
	}
	refusing := &Oid4vpPresenter{}
	_, refused := refusing.ParseRequest(context.Background(), "openid4vp://present?"+params.Encode())
	require.ErrorIs(t, refused, ErrProtocolVersionMismatch)

	for name, err := range map[string]error{
		"another presenter's refusal": refused,
		"a hand-built error":          &VersionMismatchError{Parsed: profile.VersionFinal, Version: profile.VersionDraft24, Parameter: "presentation_definition"},
		"another error":               errors.New("refused"),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := (&Oid4vpPresenter{}).AdmitUnderVersion(context.Background(), err)
			require.ErrorIs(t, err, ErrVersionRetryUnavailable)
		})
	}
}

// A Digital Credentials API request has no Draft 24 counterpart: Presentation
// Exchange there is a request without dcql_query, not a version mismatch.
func TestDCAPIPresentationExchangeIsNotAVersionMismatch(t *testing.T) {
	invocation := types.DCAPIInvocation{Origin: "https://verifier.example", Request: types.DCAPIRequest{
		Protocol: DCAPIProtocolUnsigned,
		Data:     []byte(`{"response_type":"vp_token","response_mode":"dc_api","nonce":"n","presentation_definition":{"id":"pd"}}`),
	}}
	_, err := (&Oid4vpPresenter{}).ParseDCAPIRequest(context.Background(), invocation)
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrProtocolVersionMismatch)
	assertAuthzErrorCode(t, err, InvalidRequestError)
}

// The other direction: a dcql_query Request Object that reached the Draft 24
// entry point is admitted as OpenID4VP 1.0 under the presenter's profile. A
// presenter requiring delivery by reference (HAIP 1.0 §5.1) accepts the one it
// fetched from request_uri, and refuses the same Request Object passed by
// value.
func TestDraft24EntryPointHandsADCQLRequestToFinal(t *testing.T) {
	f := newRequestObjectFixture(t, "verifier.example")
	claims := f.claims()
	claims["client_id"] = draft24X509ClientID
	fetches := f.countingDraft24Handler(t, claims)
	byReference, err := profile.Final().With(profile.Options{RequireSignedRequestByReference: true})
	require.NoError(t, err)
	p := f.sealedPresenter(byReference, f.now)
	uri := "openid4vp://authorize?" + url.Values{"client_id": {draft24X509ClientID}, "request_uri": {f.server.URL + "/request-object"}}.Encode()
	_, err = p.ParseDraft24Request(context.Background(), uri)
	require.ErrorIs(t, err, ErrProtocolVersionMismatch)
	admitted, err := p.AdmitUnderVersion(context.Background(), err)
	require.NoError(t, err)
	handle := admitted.(*AdmittedRequest)
	require.False(t, handle.Draft24())
	require.EqualValues(t, 1, fetches.Load())
	require.Equal(t, "reference", handle.Request().RequestObjectVerification.Delivery)

	_, err = p.ParseDraft24RequestObject(context.Background(), f.sign(t, claims, nil), types.RequestObjectSource{ClientID: draft24X509ClientID})
	require.ErrorIs(t, err, ErrProtocolVersionMismatch)
	_, err = p.AdmitUnderVersion(context.Background(), err)
	require.ErrorIs(t, err, ErrRequestURIRequired)
}
