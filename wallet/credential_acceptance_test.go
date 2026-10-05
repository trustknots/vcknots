package wallet

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/trustknots/vcknots/wallet/acceptance"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/credstore"
	"github.com/trustknots/vcknots/wallet/credstore/plugins/local"
	credstoreTypes "github.com/trustknots/vcknots/wallet/credstore/types"
	"github.com/trustknots/vcknots/wallet/internal/testutil"
	"github.com/trustknots/vcknots/wallet/profile"
	"github.com/trustknots/vcknots/wallet/receiver"
	"github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

type acceptanceFixture struct {
	wallet *Wallet
	store  *credstore.CredStoreDispatcher
	server *httptest.Server
	wireCh chan string
	holder *mockKeyEntry
}

func newAcceptanceStore(t *testing.T) *credstore.CredStoreDispatcher {
	t.Helper()
	storage, err := local.NewLocalCredentialStorage(filepath.Join(t.TempDir(), "credentials.db"))
	require.NoError(t, err)
	store, err := credstore.NewCredStoreDispatcher(credstore.WithPlugin(local.Local, storage))
	require.NoError(t, err)
	return store
}

func acceptanceEntryCount(t *testing.T, store *credstore.CredStoreDispatcher) int {
	t.Helper()
	result, err := store.GetCredentialEntries(0, nil, credstoreTypes.SupportedCredStoreTypes(0))
	require.NoError(t, err)
	if result.Entries == nil {
		return 0
	}
	return len(*result.Entries)
}

// newAcceptanceWallet builds a wallet with an explicit protocol profile and no
// receiver plugin: the acceptance path runs on a credential the test already
// holds, so no issuance transport is needed to reach it.
func newAcceptanceWallet(t *testing.T, p profile.Profile, policy *acceptance.Policy) (*Wallet, *credstore.CredStoreDispatcher) {
	t.Helper()
	store := newAcceptanceStore(t)
	w, err := NewWalletWithConfig(Config{Profiles: profilesFor(p), CredStore: store, CredentialAcceptance: policy})
	require.NoError(t, err)
	return w, store
}

func newAcceptanceFixture(t *testing.T, policy *acceptance.Policy) *acceptanceFixture {
	t.Helper()
	store := newAcceptanceStore(t)

	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	writeJSON := func(w http.ResponseWriter, value any) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(value); err != nil {
			t.Error(err)
		}
	}
	mux.HandleFunc("/.well-known/openid-credential-issuer", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"credential_issuer":     server.URL,
			"credential_endpoint":   server.URL + "/credential",
			"nonce_endpoint":        server.URL + "/nonce",
			"authorization_servers": []string{server.URL},
			"credential_configurations_supported": map[string]any{
				"acceptance-config": map[string]any{"format": "vc+sd-jwt", "vct": "urn:test:acceptance"},
			},
		})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":         server.URL,
			"token_endpoint": server.URL + "/token",
			"pre-authorized_grant_anonymous_access_supported": true,
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"access_token": "acceptance-token", "token_type": "Bearer", "c_nonce": "acceptance-nonce"})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"c_nonce": "acceptance-nonce"})
	})
	wireCh := make(chan string, 1)
	mux.HandleFunc("/credential", func(w http.ResponseWriter, r *http.Request) {
		select {
		case wire := <-wireCh:
			writeJSON(w, map[string]any{"credential": wire})
		case <-r.Context().Done():
		}
	})

	receiving, err := receiver.NewReceivingDispatcher(receiver.WithPlugin(receiverTypes.Oid4vci, &oid4vci.Oid4vciReceiver{HTTPClient: server.Client()}))
	require.NoError(t, err)
	w, err := NewWalletWithConfig(Config{CredStore: store, Receiver: receiving, CredentialAcceptance: policy})
	require.NoError(t, err)
	return &acceptanceFixture{wallet: w, store: store, server: server, wireCh: wireCh, holder: newMockKeyEntry()}
}

func (f *acceptanceFixture) send(wire string) {
	f.wireCh <- wire
}

func (f *acceptanceFixture) receive(t *testing.T) (*SavedCredential, error) {
	t.Helper()
	return f.receiveUnder(t, nil)
}

// receiveUnder runs the Draft 13 Pre-Authorized Code Flow begun with a
// per-request acceptance policy; nil applies Config.CredentialAcceptance.
func (f *acceptanceFixture) receiveUnder(t *testing.T, policy *acceptance.Policy) (*SavedCredential, error) {
	t.Helper()
	issuer, err := url.Parse(f.server.URL)
	require.NoError(t, err)
	return receiveDraft13(t.Context(), f.wallet,
		PreAuthorizedIssuanceRequest{CredentialOffer: preAuthorizedCodeOffer(issuer, "acceptance-config", "code"), Acceptance: policy},
		CredentialRequest{HolderKeys: []IKeyEntry{f.holder}})
}

// storeCredential runs the Draft 13 store path over wire under the wallet's
// Config.CredentialAcceptance.
func (f *acceptanceFixture) storeCredential(t *testing.T, wire string, holder *jose.JSONWebKey) (*SavedCredential, error) {
	t.Helper()
	policy, err := f.wallet.acceptancePolicy(nil)
	if err != nil {
		return nil, err
	}
	return f.wallet.storeAndParseCredential(t.Context(), policy, testIssuerIdentifier, &wire, credential.SDJwtVC, holder)
}

func (f *acceptanceFixture) entryCount(t *testing.T) int {
	t.Helper()
	return acceptanceEntryCount(t, f.store)
}

type acceptanceWire struct {
	issuer string
	vct    string
	typ    string
	cnf    *jose.JSONWebKey
	// cnfRaw sets the confirmation object verbatim and takes precedence over
	// cnf, so a test can build the confirmation methods the wallet refuses.
	cnfRaw          map[string]any
	exp             time.Time
	nbf             *time.Time
	disclosures     map[string]string
	extraDisclosure bool
	// sdAlg overrides the _sd_alg claim written next to the disclosure
	// digests, so a hash the wallet does not accept can be offered.
	sdAlg string
	x5c   []string
	// signingKey is the ECDSA issuer key of an ES256 credential, which is what
	// most cases need. alg and signer together replace it when the credential
	// must be signed with another algorithm or key type.
	signingKey      *ecdsa.PrivateKey
	alg             jose.SignatureAlgorithm
	signer          any
	kid             string
	tamperSignature bool
}

func buildAcceptanceWire(t *testing.T, spec acceptanceWire) string {
	t.Helper()
	if spec.typ == "" {
		spec.typ = "dc+sd-jwt"
	}
	if spec.issuer == "" {
		spec.issuer = "https://issuer.example.test"
	}
	if spec.vct == "" {
		spec.vct = "urn:test:acceptance"
	}
	if spec.exp.IsZero() {
		spec.exp = time.Now().Add(time.Hour)
	}
	if spec.alg == "" {
		spec.alg = jose.ES256
	}
	if spec.signer == nil {
		require.NotNil(t, spec.signingKey)
		spec.signer = spec.signingKey
	}

	claims := map[string]any{
		"iss": spec.issuer,
		"vct": spec.vct,
		"iat": time.Now().Unix(),
		"exp": spec.exp.Unix(),
	}
	if spec.nbf != nil {
		claims["nbf"] = spec.nbf.Unix()
	}
	switch {
	case spec.cnfRaw != nil:
		claims["cnf"] = spec.cnfRaw
	case spec.cnf != nil:
		claims["cnf"] = map[string]any{"jwk": spec.cnf.Public()}
	}

	var disclosures, hashes []string
	names := make([]string, 0, len(spec.disclosures))
	for name := range spec.disclosures {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		raw, err := json.Marshal([]any{"salt-" + name, name, spec.disclosures[name]})
		require.NoError(t, err)
		encoded := base64.RawURLEncoding.EncodeToString(raw)
		disclosures = append(disclosures, encoded)
		digest := sha256.Sum256([]byte(encoded))
		hashes = append(hashes, base64.RawURLEncoding.EncodeToString(digest[:]))
	}
	if len(hashes) > 0 {
		claims["_sd"] = hashes
		claims["_sd_alg"] = "sha-256"
		if spec.sdAlg != "" {
			claims["_sd_alg"] = spec.sdAlg
		}
	}
	if spec.extraDisclosure {
		raw, err := json.Marshal([]any{"orphan-salt", "orphan_claim", "orphan-value"})
		require.NoError(t, err)
		disclosures = append(disclosures, base64.RawURLEncoding.EncodeToString(raw))
	}

	signerOptions := (&jose.SignerOptions{}).WithType(jose.ContentType(spec.typ))
	if len(spec.x5c) > 0 {
		signerOptions = signerOptions.WithHeader("x5c", spec.x5c)
	}
	if spec.kid != "" {
		signerOptions = signerOptions.WithHeader("kid", spec.kid)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: spec.alg, Key: spec.signer}, signerOptions)
	require.NoError(t, err)
	signed, err := jwt.Signed(signer).Claims(claims).Serialize()
	require.NoError(t, err)
	wire := strings.Join(append([]string{signed}, disclosures...), "~") + "~"
	if spec.tamperSignature {
		wire = tamperIssuerSignature(t, wire)
	}
	return wire
}

func tamperIssuerSignature(t *testing.T, wire string) string {
	t.Helper()
	parts := strings.SplitN(wire, "~", 2)
	jwtParts := strings.Split(parts[0], ".")
	require.Len(t, jwtParts, 3)
	signature, err := base64.RawURLEncoding.DecodeString(jwtParts[2])
	require.NoError(t, err)
	require.NotEmpty(t, signature)
	signature[0] ^= 0xFF
	jwtParts[2] = base64.RawURLEncoding.EncodeToString(signature)
	return strings.Join(jwtParts, ".") + "~" + parts[1]
}

type testIssuerChain struct {
	caCert   *x509.Certificate
	caKey    *ecdsa.PrivateKey
	leafCert *x509.Certificate
	leafKey  *ecdsa.PrivateKey
}

func (c testIssuerChain) x5c() []string {
	return []string{
		base64.StdEncoding.EncodeToString(c.leafCert.Raw),
		base64.StdEncoding.EncodeToString(c.caCert.Raw),
	}
}

func (c testIssuerChain) anchors() []*x509.Certificate {
	return []*x509.Certificate{c.caCert}
}

func newTestIssuerChain(t *testing.T, dnsNames []string) testIssuerChain {
	t.Helper()
	caKey := testutil.NewP256Key(t)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Acceptance Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leafKey := testutil.NewP256Key(t)
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Acceptance Test Issuer"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dnsNames,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)
	return testIssuerChain{caCert: caCert, caKey: caKey, leafCert: leafCert, leafKey: leafKey}
}

// TestIssuanceRequiresAPolicy: SD-JWT VC -19 §2.4 requires the issuer-signed
// JWT's key to be validated, so without a policy no credential is requested
// or stored.
func TestIssuanceRequiresAPolicy(t *testing.T) {
	issuerKey := testutil.NewP256Key(t)

	t.Run("without a policy nothing is requested", func(t *testing.T) {
		fixture := newAcceptanceFixture(t, nil)
		holder := fixture.holder.PublicKey()
		fixture.send(buildAcceptanceWire(t, acceptanceWire{cnf: &holder, signingKey: issuerKey}))
		_, err := fixture.receive(t)
		require.ErrorIs(t, err, ErrCredentialAcceptancePolicyRequired)
		require.Len(t, fixture.wireCh, 1, "the credential endpoint must not be called")
		require.Equal(t, 0, fixture.entryCount(t))
	})

	t.Run("a per-request policy stores the authenticated credential", func(t *testing.T) {
		fixture := newAcceptanceFixture(t, nil)
		holder := fixture.holder.PublicKey()
		fixture.send(buildAcceptanceWire(t, acceptanceWire{cnf: &holder, signingKey: issuerKey}))
		saved, err := fixture.receiveUnder(t, acceptIssuerKeyPolicy(issuerKey))
		require.NoError(t, err)
		require.True(t, saved.Verification.HolderBound)
		require.NotEmpty(t, saved.Verification.Mechanism)
		require.Equal(t, 1, fixture.entryCount(t))
	})

	t.Run("an issuer the policy cannot authenticate is not stored", func(t *testing.T) {
		fixture := newAcceptanceFixture(t, nil)
		holder := fixture.holder.PublicKey()
		fixture.send(buildAcceptanceWire(t, acceptanceWire{cnf: &holder, signingKey: testutil.NewP256Key(t)}))
		_, err := fixture.receiveUnder(t, acceptIssuerKeyPolicy(issuerKey))
		require.ErrorIs(t, err, acceptance.ErrIssuerSignatureInvalid)
		require.Equal(t, 0, fixture.entryCount(t))
	})
}

func TestCredentialAcceptance_HolderBinding(t *testing.T) {
	issuerKey := testutil.NewP256Key(t)

	t.Run("cnf bound to another holder key is rejected", func(t *testing.T) {
		fixture := newAcceptanceFixture(t, acceptIssuerKeyPolicy(issuerKey))
		holder := fixture.holder.PublicKey()
		otherHolder := newMockKeyEntry().PublicKey()
		wire := buildAcceptanceWire(t, acceptanceWire{cnf: &otherHolder, signingKey: issuerKey})
		_, err := fixture.storeCredential(t, wire, &holder)
		require.ErrorContains(t, err, "credential is bound to a different holder key")
		require.Equal(t, 0, fixture.entryCount(t))
	})

	t.Run("matching cnf is stored with HolderBound", func(t *testing.T) {
		fixture := newAcceptanceFixture(t, acceptIssuerKeyPolicy(issuerKey))
		holder := fixture.holder.PublicKey()
		wire := buildAcceptanceWire(t, acceptanceWire{cnf: &holder, signingKey: issuerKey})
		saved, err := fixture.storeCredential(t, wire, &holder)
		require.NoError(t, err)
		require.NotNil(t, saved.Verification)
		require.True(t, saved.Verification.HolderBound)
		require.Equal(t, 1, fixture.entryCount(t))
	})
}

func TestCredentialAcceptance_FinalResponseAllOrNothing(t *testing.T) {
	issuerKey := testutil.NewP256Key(t)
	policy := acceptIssuerKeyPolicy(issuerKey)
	fixture := newAcceptanceFixture(t, policy)
	holder := fixture.holder.PublicKey()
	valid := buildAcceptanceWire(t, acceptanceWire{cnf: &holder, signingKey: issuerKey})
	response := &receiverTypes.CredentialResponse{Credentials: []any{valid, "this-is-not-a-credential"}}
	metadata := &receiverTypes.CredentialIssuerMetadata{
		CredentialIssuer: testIssuerIdentifier,
		CredentialConfigurationSupported: map[string]receiverTypes.CredentialConfiguration{
			"acceptance-config": {Format: "dc+sd-jwt"},
		},
	}
	_, err := fixture.wallet.storeCredentialResponse(t.Context(), policy, response, metadata, "acceptance-config", []jose.JSONWebKey{holder})
	require.Error(t, err)
	require.Equal(t, 0, fixture.entryCount(t))
}

func TestVerifyCredentialForAcceptanceRequiresPolicy(t *testing.T) {
	holder := newMockKeyEntry().PublicKey()
	issuerKey := testutil.NewP256Key(t)
	signed := []byte(buildAcceptanceWire(t, acceptanceWire{cnf: &holder, signingKey: issuerKey, kid: "issuer-key-1"}))
	request := CredentialAcceptanceRequest{Raw: signed, Flavor: credential.SDJwtVC, HolderKey: &holder, CredentialIssuer: testIssuerIdentifier}

	t.Run("no policy fails closed", func(t *testing.T) {
		w, store := newAcceptanceWallet(t, profile.Final(), nil)
		_, _, err := w.VerifyCredentialForAcceptance(context.Background(), request)
		require.ErrorIs(t, err, ErrCredentialAcceptancePolicyRequired)
		require.Equal(t, 0, acceptanceEntryCount(t, store))
	})

	t.Run("a configured policy satisfies the requirement", func(t *testing.T) {
		w, _ := newAcceptanceWallet(t, profile.Final(), acceptIssuerKeyPolicy(issuerKey))
		_, verification, err := w.VerifyCredentialForAcceptance(context.Background(), request)
		require.NoError(t, err)
		require.True(t, verification.HolderBound)
	})

	t.Run("a per-request policy overrides the configured one", func(t *testing.T) {
		w, _ := newAcceptanceWallet(t, profile.Final(), acceptIssuerKeyPolicy(testutil.NewP256Key(t)))
		_, _, err := w.VerifyCredentialForAcceptance(context.Background(), request)
		require.ErrorIs(t, err, acceptance.ErrIssuerSignatureInvalid)

		overridden := request
		overridden.Acceptance = acceptIssuerKeyPolicy(issuerKey)
		_, verification, err := w.VerifyCredentialForAcceptance(context.Background(), overridden)
		require.NoError(t, err)
		require.True(t, verification.HolderBound)
	})

	t.Run("the Draft 13 issuance version admits typ vc+sd-jwt", func(t *testing.T) {
		draft := []byte(buildAcceptanceWire(t, acceptanceWire{cnf: &holder, signingKey: issuerKey, typ: "vc+sd-jwt"}))
		w, _ := newAcceptanceWallet(t, profile.Final(), acceptIssuerKeyPolicy(issuerKey))
		final := request
		final.Raw = draft
		_, _, err := w.VerifyCredentialForAcceptance(context.Background(), final)
		require.ErrorIs(t, err, acceptance.ErrCredentialTypInvalid)

		draft13 := final
		draft13.Version = profile.VersionDraft13
		w13, err := NewWalletWithConfig(Config{Profiles: []profile.Profile{profile.Final(), profile.Draft13()}, CredStore: newAcceptanceStore(t), CredentialAcceptance: acceptIssuerKeyPolicy(issuerKey)})
		require.NoError(t, err)
		_, _, err = w13.VerifyCredentialForAcceptance(context.Background(), draft13)
		require.NoError(t, err)

		haip, _ := newAcceptanceWallet(t, profile.HAIP(), acceptIssuerKeyPolicy(issuerKey))
		_, _, err = haip.VerifyCredentialForAcceptance(context.Background(), draft13)
		require.ErrorIs(t, err, ErrProfileForbidsDraft)
	})
}

// HAIP 1.0 §6.1: a credential verified apart from the
// issuance is held to the holder binding its Credential Configuration asks
// for, as RequestCredential holds it.
func TestVerifyCredentialForAcceptanceAppliesTheConfigurationsHolderBinding(t *testing.T) {
	holder := newMockKeyEntry().PublicKey()
	issuerKey := testutil.NewP256Key(t)
	unbound := []byte(buildAcceptanceWire(t, acceptanceWire{signingKey: issuerKey, kid: "issuer-key-1"}))
	methods := []string{"jwk"}
	bindingConfiguration := &receiverTypes.CredentialConfiguration{Format: "dc+sd-jwt", CryptographicBindingMethodsSupported: &methods}
	w, _ := newAcceptanceWallet(t, profile.Final(), acceptIssuerKeyPolicy(issuerKey))
	request := CredentialAcceptanceRequest{Raw: unbound, Flavor: credential.SDJwtVC, HolderKey: &holder, CredentialIssuer: testIssuerIdentifier}

	_, _, err := w.VerifyCredentialForAcceptance(context.Background(), request)
	require.NoError(t, err, "without the configuration the policy alone decides")

	request.CredentialConfiguration = bindingConfiguration
	_, _, err = w.VerifyCredentialForAcceptance(context.Background(), request)
	require.ErrorIs(t, err, acceptance.ErrHolderBindingMissing)

	request.CredentialConfiguration = &receiverTypes.CredentialConfiguration{Format: "dc+sd-jwt"}
	_, _, err = w.VerifyCredentialForAcceptance(context.Background(), request)
	require.NoError(t, err, "a configuration without binding methods asks for none")

	bound := request
	bound.Raw = []byte(buildAcceptanceWire(t, acceptanceWire{cnf: &holder, signingKey: issuerKey, kid: "issuer-key-1"}))
	bound.CredentialConfiguration = bindingConfiguration
	_, verification, err := w.VerifyCredentialForAcceptance(context.Background(), bound)
	require.NoError(t, err)
	require.True(t, verification.HolderBound)
}

func TestHAIPCredentialRejectsAnchorInX5CWithRootCAs(t *testing.T) {
	holder := newMockKeyEntry().PublicKey()
	chain := newTestIssuerChain(t, []string{"issuer.example.test"})
	wire := buildAcceptanceWire(t, acceptanceWire{signingKey: chain.leafKey, x5c: chain.x5c(), cnf: &holder})

	poolPolicy := func() *acceptance.Policy {
		roots := x509.NewCertPool()
		roots.AddCert(chain.caCert)
		return &acceptance.Policy{IssuerX509: &acceptance.IssuerX509TrustOptions{
			RootCAs:                     roots,
			AllowUnadvertisedRevocation: true,
		}}
	}

	t.Run("Final accepts the pool-trusted chain", func(t *testing.T) {
		policy := poolPolicy()
		w, store := newAcceptanceWallet(t, profile.Final(), policy)
		saved, err := w.storeAndParseCredential(t.Context(), policy, testIssuerIdentifier, &wire, credential.SDJwtVC, &holder)
		require.NoError(t, err)
		require.Len(t, saved.Verification.CertificateSHA256, 2)
		require.Equal(t, 1, acceptanceEntryCount(t, store))
	})

	t.Run("HAIP rejects the trust anchor carried in x5c", func(t *testing.T) {
		// HAIP profiles OpenID4VCI 1.0, whose acceptance applies IssuerX5C.
		w, _ := newAcceptanceWallet(t, profile.HAIP(), poolPolicy())
		_, _, err := w.VerifyCredentialForAcceptance(t.Context(), CredentialAcceptanceRequest{Raw: []byte(wire), Flavor: credential.SDJwtVC, HolderKey: &holder})
		require.ErrorContains(t, err, "profile option IssuerX5C.ExcludeAnchor")
	})
}

// TestCredentialAcceptanceStoresNothingOnFailure pins that issuance stores a
// credential only after the wallet's policy accepted it.
func TestCredentialAcceptanceStoresNothingOnFailure(t *testing.T) {
	holder := newMockKeyEntry().PublicKey()
	chain := newTestIssuerChain(t, []string{"issuer.example.test"})
	policy := &acceptance.Policy{IssuerX509: &acceptance.IssuerX509TrustOptions{TrustAnchors: chain.anchors(), AllowUnadvertisedRevocation: true}}
	wire := buildAcceptanceWire(t, acceptanceWire{signingKey: chain.leafKey, x5c: chain.x5c(), cnf: &holder})

	t.Run("an accepted credential is stored with its verification", func(t *testing.T) {
		fixture := newAcceptanceFixture(t, policy)
		saved, err := fixture.storeCredential(t, wire, &holder)
		require.NoError(t, err)
		require.Len(t, saved.Verification.CertificateSHA256, 2)
		require.Equal(t, 1, fixture.entryCount(t))
	})

	t.Run("a refused credential is not stored", func(t *testing.T) {
		fixture := newAcceptanceFixture(t, policy)
		tampered := buildAcceptanceWire(t, acceptanceWire{signingKey: chain.leafKey, x5c: chain.x5c(), cnf: &holder, tamperSignature: true})
		_, err := fixture.storeCredential(t, tampered, &holder)
		require.ErrorIs(t, err, acceptance.ErrIssuerSignatureInvalid)
		require.Equal(t, 0, fixture.entryCount(t))
	})
}

// TestVerifyCredentialForAcceptanceUsesTheWalletPolicy pins that the wallet
// method applies Config.CredentialAcceptance and reports coded errors that
// match both the wallet and the acceptance package sentinels.
func TestVerifyCredentialForAcceptanceUsesTheWalletPolicy(t *testing.T) {
	holder := newMockKeyEntry().PublicKey()
	issuerKey := testutil.NewP256Key(t)
	wire := []byte(buildAcceptanceWire(t, acceptanceWire{signingKey: issuerKey, kid: "issuer-key-1", cnf: &holder}))
	w, store := newAcceptanceWallet(t, profile.Final(), acceptIssuerKeyPolicy(issuerKey))
	request := func(holder *jose.JSONWebKey) CredentialAcceptanceRequest {
		return CredentialAcceptanceRequest{Raw: wire, Flavor: credential.SDJwtVC, HolderKey: holder, CredentialIssuer: testIssuerIdentifier}
	}

	parsed, verification, err := w.VerifyCredentialForAcceptance(t.Context(), request(&holder))
	require.NoError(t, err)
	require.NotNil(t, parsed)
	require.Equal(t, "issuer-key-1", verification.IssuerKeyID)
	require.True(t, verification.HolderBound)

	other := newMockKeyEntry().PublicKey()
	other.Key = &testutil.NewP256Key(t).PublicKey
	_, _, err = w.VerifyCredentialForAcceptance(t.Context(), request(&other))
	require.ErrorIs(t, err, acceptance.ErrHolderBindingMismatch)
	require.ErrorIs(t, err, acceptance.ErrHolderBindingMismatch)
	code, ok := ErrorCode(err)
	require.True(t, ok)
	require.Equal(t, "credential_holder_binding_mismatch", code)
	require.Equal(t, 0, acceptanceEntryCount(t, store))

	unconfigured, _ := newAcceptanceWallet(t, profile.Final(), nil)
	_, _, err = unconfigured.VerifyCredentialForAcceptance(t.Context(), request(&holder))
	require.ErrorIs(t, err, ErrCredentialAcceptancePolicyRequired)
}

// storeAndParseCredential verifies wire under policy and the Draft 13 profile
// and stores it, as the Draft 13 issuance path does after a Credential
// Response. Nothing is stored when verification fails.
func (w *Wallet) storeAndParseCredential(ctx context.Context, policy *acceptance.Policy, credentialIssuer string, wire *string, flavor credential.SupportedSerializationFlavor, holderKey *jose.JSONWebKey) (*SavedCredential, error) {
	parsed, verification, err := w.verifyCredentialUnder(ctx, profile.Draft13(), policy, []byte(*wire), flavor, holderKey, credentialIssuer)
	if err != nil {
		return nil, fmt.Errorf("failed to verify credential: %w", err)
	}
	if w.credStore == nil {
		return nil, ErrNoCredentialStore
	}
	saved := &SavedCredential{
		Credential:   parsed,
		Entry:        &credstoreTypes.CredentialEntry{Id: uuid.NewString(), ReceivedAt: time.Now(), Raw: []byte(*wire), MimeType: string(flavor)},
		Verification: verification,
	}
	if err := w.saveCredentials([]*SavedCredential{saved}); err != nil {
		return nil, err
	}
	return saved, nil
}
