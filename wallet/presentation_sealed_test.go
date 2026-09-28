package wallet

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/internal/testutil/mockserver"
	"github.com/trustknots/vcknots/wallet/presenter"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	presenterTypes "github.com/trustknots/vcknots/wallet/presenter/types"
	"github.com/trustknots/vcknots/wallet/profile"
)

var testSealKey = bytes.Repeat([]byte{0x42}, oid4vp.MinSealKeyBytes)

// sealedRequestVerifier is a Verifier of the presentation fixture that signs
// x509_hash Request Objects and serves them from request_uri.
type sealedRequestVerifier struct {
	fixture  sdjwtPresentationFixture
	keyPair  *mockserver.KeyPair
	clientID string
	roots    *x509.CertPool
	client   *http.Client
}

func newSealedRequestVerifier(t *testing.T, fixture sdjwtPresentationFixture) sealedRequestVerifier {
	t.Helper()
	keyPair := mockserver.MustGenerateKeyPair("sealed-verifier")
	leaf, err := base64.StdEncoding.DecodeString(keyPair.CertificateChain()[0])
	require.NoError(t, err)
	digest := sha256.Sum256(leaf)
	roots := x509.NewCertPool()
	for _, anchor := range mockserver.CredentialTrustAnchors() {
		roots.AddCert(anchor)
	}
	return sealedRequestVerifier{
		fixture:  fixture,
		keyPair:  keyPair,
		clientID: "x509_hash:" + base64.RawURLEncoding.EncodeToString(digest[:]),
		roots:    roots,
		client:   fixturePresenter(t, fixture.wallet).HTTPClient,
	}
}

// publish serves claims, signed, at path and returns the Authorization
// Request that names it as request_uri.
func (v sealedRequestVerifier) publish(t *testing.T, path string, claims map[string]any) string {
	t.Helper()
	claims["client_id"] = v.clientID
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: v.keyPair.PrivateKey},
		(&jose.SignerOptions{}).WithType("oauth-authz-req+jwt").WithHeader("x5c", v.keyPair.CertificateChain()))
	require.NoError(t, err)
	requestObject, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)
	v.fixture.mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
		_, _ = w.Write([]byte(requestObject))
	})
	return "openid4vp://authorize?" + url.Values{"client_id": {v.clientID}, "request_uri": {v.fixture.baseURL + path}}.Encode()
}

// claims is a signed DCQL request for the fixture's identity credential.
func (v sealedRequestVerifier) claims(responseMode string) map[string]any {
	now := time.Now()
	return map[string]any{
		"aud": "https://self-issued.me/v2", "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"response_type": "vp_token", "response_mode": responseMode, "response_uri": v.fixture.baseURL + "/response",
		"nonce": "sealed-nonce", "state": "sealed-state",
		"dcql_query": map[string]any{"credentials": []any{map[string]any{
			"id": "pid", "format": "dc+sd-jwt", "meta": map[string]any{"vct_values": []string{"urn:test:identity"}},
		}}},
	}
}

// wallet is a fresh wallet under p whose presenter trusts the Verifier, as a
// stateless integration builds one per call. It shares the fixture's
// credential store unless p is HAIP, whose wallet here is storeless.
func (v sealedRequestVerifier) wallet(t *testing.T, p profile.Profile) *Wallet {
	t.Helper()
	dispatcher, err := presenter.NewPresentationDispatcher(presenter.WithPlugin(presenter.Oid4vp, &oid4vp.Oid4vpPresenter{
		HTTPClient: v.client, X509TrustChainRoots: v.roots, Profile: p,
	}))
	require.NoError(t, err)
	config := Config{Presenter: dispatcher, CredStore: v.fixture.wallet.credStore}
	if p == profile.HAIP() {
		config = Config{Profiles: []profile.Profile{p}, Presenter: dispatcher, Storeless: true}
	}
	w, err := NewWalletWithConfig(config)
	require.NoError(t, err)
	return w
}

// A wallet whose calls are stateless answers a request it admitted by
// reference in an earlier call: the earlier handle belongs to another
// presenter, and the sealed admission carries it across.
func TestWallet_ReadmitPresentationRequestAnswersInALaterCall(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	holder := fixture.key.PublicKey()
	fixture.receive("urn:test:identity", &holder, nil, map[string]string{"given_name": "Taro"})
	verifier := newSealedRequestVerifier(t, fixture)
	uri := verifier.publish(t, "/sealed/final", verifier.claims("direct_post"))

	first := verifier.wallet(t, profile.Final())
	admitted, err := first.ParsePresentationRequest(t.Context(), uri)
	require.NoError(t, err)
	sealed, err := admitted.Seal(testSealKey)
	require.NoError(t, err)

	later := verifier.wallet(t, profile.Final())
	_, err = later.SelectCredentials(t.Context(), admitted)
	require.NoError(t, err, "selection reads the handle only")
	_, err = later.DeclinePresentation(t.Context(), admitted, "access_denied", "")
	require.ErrorIs(t, err, oid4vp.ErrRequestNotAdmittedHere, "another presenter's handle is not answered")

	readmitted, err := later.ReadmitPresentationRequest(t.Context(), sealed, testSealKey)
	require.NoError(t, err)
	selections, err := later.SelectCredentials(t.Context(), readmitted)
	require.NoError(t, err)
	_, err = later.SubmitPresentation(t.Context(), readmitted, Presentation{Key: fixture.key, Credentials: selections})
	require.NoError(t, err)
	require.Contains(t, postedVPToken(t, fixture), "pid")
}

// Under HAIP the sealed admission is how a later call answers: the Request
// Object passed by value is refused (HAIP 1.0 §5.1), a seal under another key
// is refused, and the sealed admission is admitted as delivered by reference.
func TestWallet_ReadmitPresentationRequestUnderHAIP(t *testing.T) {
	fixture := newSDJWTPresentationFixture(t)
	verifier := newSealedRequestVerifier(t, fixture)
	encryptionKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	claims := verifier.claims("direct_post.jwt")
	claims["client_metadata"] = map[string]any{
		"jwks": jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &encryptionKey.PublicKey, KeyID: "enc-1", Use: "enc", Algorithm: "ECDH-ES"}}},
		"encrypted_response_enc_values_supported": []string{"A128GCM", "A256GCM"},
	}
	uri := verifier.publish(t, "/sealed/haip", claims)

	admitted, err := verifier.wallet(t, profile.HAIP()).ParsePresentationRequest(t.Context(), uri)
	require.NoError(t, err)
	sealed, err := admitted.Seal(testSealKey)
	require.NoError(t, err)

	later := verifier.wallet(t, profile.HAIP())
	_, err = later.ParsePresentationRequestObject(t.Context(), admitted.RequestObject(), presenterTypes.RequestObjectSource{ClientID: verifier.clientID})
	require.ErrorIs(t, err, oid4vp.ErrRequestURIRequired)

	_, err = later.ReadmitPresentationRequest(t.Context(), sealed, bytes.Repeat([]byte{0x24}, oid4vp.MinSealKeyBytes))
	require.ErrorIs(t, err, oid4vp.ErrSealedAdmissionInvalid)
	code, coded := common.CodeOf(err)
	require.True(t, coded)
	require.Equal(t, "sealed_admission_invalid", string(code))

	readmitted, err := later.ReadmitPresentationRequest(t.Context(), sealed, testSealKey)
	require.NoError(t, err)
	request := readmitted.Request()
	require.Equal(t, "reference", request.RequestObjectVerification.Delivery)
	require.Equal(t, "sealed-nonce", request.Nonce)
}
