package common

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet"
	"github.com/trustknots/vcknots/wallet/credstore"
	"github.com/trustknots/vcknots/wallet/idprof"
	"github.com/trustknots/vcknots/wallet/presenter"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	"github.com/trustknots/vcknots/wallet/receiver"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
	"github.com/trustknots/vcknots/wallet/serializer"
	"github.com/trustknots/vcknots/wallet/verifier"
)

const DefaultCertPath = "../../../server/samples/certificate-openid-test/certificate_openid.pem"

type MockKeyEntry struct {
	id         string
	privateKey *ecdsa.PrivateKey
}

func NewMockKeyEntry() *MockKeyEntry {
	xBytes, _ := base64.RawURLEncoding.DecodeString("ezZgKwMueAyZLHUgSpzNkbOWDgjJXTAOJn8MftOnayQ")
	yBytes, _ := base64.RawURLEncoding.DecodeString("Fy_U4KyZQf-9jKpFJtH6OFFRXmwAcveyfuoDp1hSOFo")
	dBytes, _ := base64.RawURLEncoding.DecodeString("jAfOh_53IRxqpEsFojZK8iHP--L8ol3ePEo3DnwiIyM")

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	d := new(big.Int).SetBytes(dBytes)

	privateKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		},
		D: d,
	}

	return &MockKeyEntry{
		id:         "test-key-id",
		privateKey: privateKey,
	}
}

func (m *MockKeyEntry) ID() string {
	return m.id
}

func (m *MockKeyEntry) PublicKey() jose.JSONWebKey {
	return jose.JSONWebKey{
		Key:       &m.privateKey.PublicKey,
		Algorithm: "ES256",
		Use:       "sig",
	}
}

func (m *MockKeyEntry) Sign(payload []byte) ([]byte, error) {
	hash := sha256.Sum256(payload)

	r, s, err := ecdsa.Sign(rand.Reader, m.privateKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign with ECDSA: %w", err)
	}

	signature := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(signature[32-len(rBytes):32], rBytes)
	copy(signature[64-len(sBytes):64], sBytes)

	return signature, nil
}

type Runtime struct {
	CredStore  *credstore.CredStoreDispatcher
	Serializer *serializer.SerializationDispatcher
	Wallet     *wallet.Wallet
}

func NewOID4VPRuntime(certPath string) (*Runtime, error) {
	credStore, err := credstore.NewCredStoreDispatcher(credstore.WithDefaultConfig())
	if err != nil {
		return nil, err
	}

	receiverDispatcher, err := receiver.NewReceivingDispatcher(receiver.WithDefaultConfig())
	if err != nil {
		return nil, err
	}

	serializerDispatcher, err := serializer.NewSerializationDispatcher(serializer.WithDefaultConfig())
	if err != nil {
		return nil, err
	}

	verifierDispatcher, err := verifier.NewVerificationDispatcher(verifier.WithDefaultConfig())
	if err != nil {
		return nil, err
	}

	if certPath == "" {
		certPath = DefaultCertPath
	}

	certFile, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(certFile) {
		return nil, fmt.Errorf("failed to parse certificate")
	}

	oid4vpPresenter := &oid4vp.Oid4vpPresenter{
		X509TrustChainRoots: certPool,
	}
	presenterDispatcher, err := presenter.NewPresentationDispatcher(
		presenter.WithPlugin(presenter.Oid4vp, oid4vpPresenter),
	)
	if err != nil {
		return nil, err
	}

	idProf, err := idprof.NewIdentityProfileDispatcher(idprof.WithDefaultConfig())
	if err != nil {
		return nil, err
	}

	w, err := wallet.NewWalletWithConfig(wallet.Config{
		CredStore:  credStore,
		IDProfiler: idProf,
		Receiver:   receiverDispatcher,
		Serializer: serializerDispatcher,
		Verifier:   verifierDispatcher,
		Presenter:  presenterDispatcher,
	})
	if err != nil {
		return nil, err
	}

	return &Runtime{
		CredStore:  credStore,
		Serializer: serializerDispatcher,
		Wallet:     w,
	}, nil
}

const credentialOfferURIPrefix = "openid-credential-offer://?credential_offer="

// ReceiveCredentialFromOffer fetches a credential offer from the issuer's offer
// endpoint, then runs the OID4VCI pre-authorized-code flow to receive and store
// the credential. format is the OID4VCI credential format to request, e.g.
// "jwt_vc_json" or "dc+sd-jwt".
func ReceiveCredentialFromOffer(
	w *wallet.Wallet,
	key *MockKeyEntry,
	offerEndpoint string,
	format string,
) (*wallet.SavedCredential, error) {
	resp, err := http.Post(offerEndpoint, "application/json", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch credential offer: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read offer response: %w", err)
	}

	offer, err := parseCredentialOffer(string(body))
	if err != nil {
		return nil, err
	}

	return w.ReceiveCredential(wallet.ReceiveCredentialRequest{
		CredentialOffer: offer,
		Type:            receiverTypes.Oid4vci,
		Key:             key,
		Format:          format,
	})
}

// parseCredentialOffer parses an "openid-credential-offer://" URI into a
// wallet.CredentialOffer.
func parseCredentialOffer(offerURI string) (*wallet.CredentialOffer, error) {
	offerURI = strings.TrimSpace(offerURI)
	if !strings.HasPrefix(offerURI, credentialOfferURIPrefix) {
		return nil, fmt.Errorf("invalid offer URI format: %q", offerURI)
	}

	decodedOffer, err := url.QueryUnescape(strings.TrimPrefix(offerURI, credentialOfferURIPrefix))
	if err != nil {
		return nil, fmt.Errorf("failed to decode offer: %w", err)
	}

	var offerData struct {
		CredentialIssuer           string   `json:"credential_issuer"`
		CredentialConfigurationIDs []string `json:"credential_configuration_ids"`
		Grants                     map[string]struct {
			PreAuthorizedCode string `json:"pre-authorized_code"`
		} `json:"grants"`
	}
	if err := json.Unmarshal([]byte(decodedOffer), &offerData); err != nil {
		return nil, fmt.Errorf("failed to parse offer JSON: %w", err)
	}

	issuerURL, err := url.Parse(offerData.CredentialIssuer)
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential issuer URL: %w", err)
	}

	grants := make(map[string]*wallet.CredentialOfferGrant, len(offerData.Grants))
	for grantType, grant := range offerData.Grants {
		grants[grantType] = &wallet.CredentialOfferGrant{PreAuthorizedCode: grant.PreAuthorizedCode}
	}

	return &wallet.CredentialOffer{
		CredentialIssuer:           issuerURL,
		CredentialConfigurationIDs: offerData.CredentialConfigurationIDs,
		Grants:                     grants,
	}, nil
}
