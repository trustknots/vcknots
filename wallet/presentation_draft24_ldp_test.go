package wallet

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/credential/dataintegrity"
	credstoreTypes "github.com/trustknots/vcknots/wallet/credstore/types"
	"github.com/trustknots/vcknots/wallet/presenter"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	presenterTypes "github.com/trustknots/vcknots/wallet/presenter/types"
	"github.com/trustknots/vcknots/wallet/serializer/plugins/ldpvc"
)

// ed25519KeyEntry is the holder key of an ldp_vp: Sign returns the RFC 8032
// signature of the bytes it is given.
type ed25519KeyEntry struct{ private ed25519.PrivateKey }

func (k ed25519KeyEntry) ID() string { return "holder-ed25519" }
func (k ed25519KeyEntry) PublicKey() jose.JSONWebKey {
	return jose.JSONWebKey{Key: k.private.Public().(ed25519.PublicKey), Algorithm: string(jose.EdDSA)}
}
func (k ed25519KeyEntry) Sign(data []byte) ([]byte, error) { return ed25519.Sign(k.private, data), nil }

// ldpPresentationVectors reuses the credential/dataintegrity vectors, which an
// independent Data Integrity implementation produced: a credential the issuer
// signed there must present here, under the same holder DID.
type ldpPresentationVectors struct {
	Issuer struct {
		PrivateJWK struct{ D string } `json:"privateJwk"`
	} `json:"issuer"`
	Holder struct {
		PrivateJWK struct{ D string } `json:"privateJwk"`
		VM         string             `json:"vm"`
	} `json:"holder"`
	Cases []struct {
		Credential map[string]any `json:"credential"`
	} `json:"cases"`
	Contexts   map[string]any `json:"contexts"`
	ContextURL string         `json:"contextUrl"`
}

func loadLdpPresentationVectors(t *testing.T) ldpPresentationVectors {
	t.Helper()
	raw, err := os.ReadFile("credential/dataintegrity/testdata/vectors.json")
	require.NoError(t, err)
	var vectors ldpPresentationVectors
	require.NoError(t, json.Unmarshal(raw, &vectors))
	return vectors
}

func seedKey(t *testing.T, encoded string) ed25519.PrivateKey {
	t.Helper()
	seed, err := base64.RawURLEncoding.DecodeString(encoded)
	require.NoError(t, err)
	return ed25519.NewKeyFromSeed(seed)
}

type ldpPresentationFixture struct {
	wallet     *Wallet
	presenting *presenter.PresentationDispatcher
	baseURL    string
	posted     chan url.Values
	vectors    ldpPresentationVectors
	holder     ed25519KeyEntry
}

func newLdpPresentationFixture(t *testing.T) ldpPresentationFixture {
	t.Helper()
	posted := make(chan url.Values, 2)
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	mux.HandleFunc("/response", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		posted <- r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"redirect_uri":"` + server.URL + `/done"}`))
	})
	presenting, err := presenter.NewPresentationDispatcher(presenter.WithPlugin(presenter.Oid4vp, &oid4vp.Oid4vpPresenter{HTTPClient: server.Client()}))
	require.NoError(t, err)
	controller, err := NewWalletWithConfig(Config{Presenter: presenting, Storeless: true})
	require.NoError(t, err)
	vectors := loadLdpPresentationVectors(t)
	return ldpPresentationFixture{
		wallet:     controller,
		presenting: presenting,
		baseURL:    server.URL,
		posted:     posted,
		vectors:    vectors,
		holder:     ed25519KeyEntry{private: seedKey(t, vectors.Holder.PrivateJWK.D)},
	}
}

// request admits the fixture's Draft 24 request on w.
func (f ldpPresentationFixture) request(t *testing.T, w *Wallet) *oid4vp.AdmittedRequest {
	t.Helper()
	return parseDraft24(t, w, draft24PresentationURI(f.baseURL, "direct_post", ""))
}

// present submits selections with the fixture's holder key and LDP options.
func (f ldpPresentationFixture) present(t *testing.T, w *Wallet, key IKeyEntry, options *ldpvc.LdpVcPresentationOptions, selections ...CredentialSelection) (string, error) {
	t.Helper()
	result, err := w.SubmitPresentation(t.Context(), f.request(t, w), Presentation{Key: key, Credentials: selections, SerializeOptions: options})
	if err != nil {
		return "", err
	}
	return result.RedirectURI, nil
}

func (f ldpPresentationFixture) selection(t *testing.T, id string, descriptors ...string) CredentialSelection {
	t.Helper()
	raw, err := json.Marshal(f.vectors.Cases[0].Credential)
	require.NoError(t, err)
	return CredentialSelection{
		Credential: &credstoreTypes.CredentialEntry{
			Id:         id,
			ReceivedAt: time.Now(),
			Raw:        raw,
			MimeType:   string(credential.LdpVc),
		},
		QueryIDs: descriptors,
	}
}

func (f ldpPresentationFixture) options() *ldpvc.LdpVcPresentationOptions {
	return &ldpvc.LdpVcPresentationOptions{
		Context:  f.vectors.ContextURL,
		Contexts: f.vectors.Contexts,
	}
}

// An ldp_vp answers a Presentation Exchange request with one Verifiable
// Presentation that embeds the credentials and is bound to the request by an
// authentication proof whose challenge is the nonce and whose domain is the
// client_id (OpenID4VP Appendix B.1.3.1).
func TestWallet_SubmitPresentationDraft24SignsAnLdpVp(t *testing.T) {
	fixture := newLdpPresentationFixture(t)

	redirect, err := fixture.present(t, fixture.wallet, fixture.holder, fixture.options(),
		fixture.selection(t, "degree-1", "identity"),
		fixture.selection(t, "degree-2", "address"),
	)
	require.NoError(t, err)
	require.Equal(t, fixture.baseURL+"/done", redirect)

	form := <-fixture.posted
	require.Equal(t, "state-to-preserve", form.Get("state"))
	var presentation map[string]any
	require.NoError(t, json.Unmarshal([]byte(form.Get("vp_token")), &presentation))
	require.Equal(t, fixture.vectors.ContextURL, presentation["@context"])
	require.Equal(t, []any{"VerifiablePresentation"}, presentation["type"])
	holderDID := "did:key:z6MkqGC3nWZhYieEVTVDKW5v588CiGfsDSmRVG9ZwwWTvLSK"
	require.Equal(t, holderDID, presentation["holder"])
	require.Len(t, presentation["verifiableCredential"], 2)

	proof := presentation["proof"].(map[string]any)
	require.Equal(t, "authentication", proof["proofPurpose"])
	require.Equal(t, "presentation-nonce", proof["challenge"])
	require.Equal(t, "redirect_uri:"+fixture.baseURL+"/response", proof["domain"])
	require.Equal(t, fixture.vectors.Holder.VM, proof["verificationMethod"])
	holderPublic := fixture.holder.private.Public().(ed25519.PublicKey)
	require.NoError(t, dataintegrity.VerifyEddsaRdfc2022(presentation, fixture.vectors.Contexts, holderPublic))
	issuerPublic := seedKey(t, fixture.vectors.Issuer.PrivateJWK.D).Public().(ed25519.PublicKey)
	for _, embedded := range presentation["verifiableCredential"].([]any) {
		require.NoError(t, dataintegrity.VerifyEddsaRdfc2022(embedded.(map[string]any), fixture.vectors.Contexts, issuerPublic))
	}

	var submission presenterTypes.PresentationSubmission
	require.NoError(t, json.Unmarshal([]byte(form.Get("presentation_submission")), &submission))
	require.Equal(t, "definition-1", submission.DefinitionID)
	require.Len(t, submission.DescriptorMap, 2)
	for index, descriptor := range []string{"identity", "address"} {
		item := submission.DescriptorMap[index]
		require.Equal(t, descriptor, item.ID)
		require.Equal(t, "ldp_vp", item.Format)
		require.Equal(t, "$", item.Path)
		require.NotNil(t, item.PathNested)
		require.Equal(t, "ldp_vc", item.PathNested.Format)
		require.Equal(t, []string{"$.verifiableCredential[0]", "$.verifiableCredential[1]"}[index], item.PathNested.Path)
	}
}

// The options the caller passes are not written back: a second presentation
// with the same options object is bound to its own request.
func TestWallet_SubmitPresentationDraft24DoesNotMutateLdpOptions(t *testing.T) {
	fixture := newLdpPresentationFixture(t)
	options := fixture.options()
	_, err := fixture.present(t, fixture.wallet, fixture.holder, options, fixture.selection(t, "degree-1", "identity"))
	require.NoError(t, err)
	<-fixture.posted
	require.Empty(t, options.Challenge)
	require.Empty(t, options.Domain)
}

func TestWallet_SubmitPresentationDraft24LdpRefusesANonEd25519Key(t *testing.T) {
	fixture := newLdpPresentationFixture(t)
	_, err := fixture.present(t, fixture.wallet, newMockKeyEntry(), fixture.options(), fixture.selection(t, "degree-1", "identity"))
	require.Error(t, err)
	require.Len(t, fixture.posted, 0, "nothing may be sent when the proof cannot be made")
}

func TestWallet_SubmitPresentationDraft24LdpRefusesAnUnpinnedContext(t *testing.T) {
	fixture := newLdpPresentationFixture(t)
	options := fixture.options()
	options.Context = []any{fixture.vectors.ContextURL, "https://www.w3.org/ns/credentials/v2"}
	_, err := fixture.present(t, fixture.wallet, fixture.holder, options, fixture.selection(t, "degree-1", "identity"))
	require.ErrorIs(t, err, dataintegrity.ErrContextNotPinned)
	require.Len(t, fixture.posted, 0)
}

// TestHooks.PresentationExchangeResponse sees the finished response and what
// it returns is what the Verifier receives; its refusal stops the
// presentation before sending.
func TestWallet_SubmitPresentationAppliesTheResponseTransform(t *testing.T) {
	fixture := newLdpPresentationFixture(t)
	hooked := func(transform Draft24ResponseTransform) *Wallet {
		w, err := NewWalletWithConfig(Config{Presenter: fixture.presenting, Storeless: true, TestHooks: &TestHooks{PresentationExchangeResponse: transform}})
		require.NoError(t, err)
		return w
	}

	rewriting := hooked(func(vpToken []byte, submission presenterTypes.PresentationSubmission) ([]byte, presenterTypes.PresentationSubmission, error) {
		var presentation map[string]any
		require.NoError(t, json.Unmarshal(vpToken, &presentation))
		require.Contains(t, presentation, "proof")
		submission.DescriptorMap[0].ID = "renamed"
		return []byte(`{"rewritten":true}`), submission, nil
	})
	_, err := fixture.present(t, rewriting, fixture.holder, fixture.options(), fixture.selection(t, "degree-1", "identity"))
	require.NoError(t, err)
	form := <-fixture.posted
	require.JSONEq(t, `{"rewritten":true}`, form.Get("vp_token"))
	require.Contains(t, form.Get("presentation_submission"), `"id":"renamed"`)

	refusal := errors.New("knob refused")
	refusing := hooked(func([]byte, presenterTypes.PresentationSubmission) ([]byte, presenterTypes.PresentationSubmission, error) {
		return nil, presenterTypes.PresentationSubmission{}, refusal
	})
	_, err = fixture.present(t, refusing, fixture.holder, fixture.options(), fixture.selection(t, "degree-1", "identity"))
	require.ErrorIs(t, err, ErrDraft24ResponseTransformFailed)
	require.ErrorIs(t, err, refusal)
	require.Len(t, fixture.posted, 0)
}
