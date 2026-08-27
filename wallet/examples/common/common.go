package common

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"
	"os"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet"
	"github.com/trustknots/vcknots/wallet/clientconfig"
	"github.com/trustknots/vcknots/wallet/credstore"
	"github.com/trustknots/vcknots/wallet/idprof"
	"github.com/trustknots/vcknots/wallet/presenter"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	"github.com/trustknots/vcknots/wallet/receiver"
	"github.com/trustknots/vcknots/wallet/serializer"
	"github.com/trustknots/vcknots/wallet/verifier"
)

const DefaultCertPath = "../../../server/samples/certificate-openid-test/certificate_openid.pem"

// Paths of the sample client registration shared by the local server
// integration examples. They are relative to each example's own directory.
const (
	DefaultClientConfigPath     = "../config/wallet-clients.json"
	DefaultClientPrivateJWKPath = "../config/client-private.sample.jwks.json"
	DefaultClientID             = "test-client-id"
)

// LoadClientAuth reads the sample client registration used by the local server
// integration examples. The public half of the key it selects is the one
// registered as test-client-id in server/samples/oauth-clients.json.
//
// AllowInsecureFilePermissions is passed deliberately: the sample private key
// is committed so that the examples run straight after a clone, and git does
// not preserve file modes. A real deployment keeps its signing key out of the
// repository with mode 0600 and lets the permission check run.
func LoadClientAuth() (wallet.ClientAuthConfig, error) {
	return clientconfig.Load(
		DefaultClientConfigPath,
		clientconfig.WithClientID(DefaultClientID),
		clientconfig.WithPrivateJWKFile(DefaultClientPrivateJWKPath),
		clientconfig.AllowInsecureFilePermissions(),
	)
}

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
		id:         "client-key-1",
		privateKey: privateKey,
	}
}

func (m *MockKeyEntry) ID() string {
	return m.id
}

func (m *MockKeyEntry) PublicKey() jose.JSONWebKey {
	return jose.JSONWebKey{
		Key:       &m.privateKey.PublicKey,
		KeyID:     m.id,
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

	clientAuth, err := LoadClientAuth()
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
		ClientAuth: clientAuth,
		DPoP: wallet.DPoPConfig{
			Enabled: true,
			Key:     clientAuth.Key,
		},
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
