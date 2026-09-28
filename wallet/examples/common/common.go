package common

import (
	"context"
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
	"github.com/trustknots/vcknots/wallet/acceptance"
	"github.com/trustknots/vcknots/wallet/clientconfig"
	"github.com/trustknots/vcknots/wallet/credstore"
	"github.com/trustknots/vcknots/wallet/experimental"
	"github.com/trustknots/vcknots/wallet/idprof"
	"github.com/trustknots/vcknots/wallet/idprof/issuerkeys"
	"github.com/trustknots/vcknots/wallet/presenter"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	"github.com/trustknots/vcknots/wallet/receiver"
	"github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
	"github.com/trustknots/vcknots/wallet/serializer"
	serializerTypes "github.com/trustknots/vcknots/wallet/serializer/types"
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

// SampleIssuerAcceptance is the credential acceptance policy of the
// examples. The local sample server publishes JWT VC Issuer Metadata at
// /.well-known/jwt-vc-issuer (SD-JWT VC -19 §4), which authenticates its
// SD-JWT VCs; a DID issuer is accepted once the Credential Issuer's origin
// links it with a DID Configuration. The local sample server runs on plain
// http, so allowHTTP lets the key resolution reach it through the
// experimental setting; it is not for production use. When issuerCAPath names
// a PEM file, a credential carrying x5c is authenticated against the
// certificates in it; its iss must be a host the leaf certificate names
// (allowHTTP binds an http iss the same way).
func SampleIssuerAcceptance(issuerCAPath string, allowHTTP bool) (*acceptance.Policy, error) {
	policy := &acceptance.Policy{IssuerKeys: &issuerkeys.Resolver{
		Mechanisms: issuerkeys.Mechanisms{
			JWTVCIssuerMetadata: true, RemoteJWKS: true,
			DIDKey: true, DIDJWK: true, DIDWeb: true, DIDConfiguration: true,
		},
		Experimental: experimental.Transport{AllowHTTP: allowHTTP},
	}}
	if issuerCAPath == "" {
		return policy, nil
	}
	pem, err := os.ReadFile(issuerCAPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read issuer CA certificates: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("failed to parse issuer CA certificates")
	}
	policy.IssuerX509 = &acceptance.IssuerX509TrustOptions{
		RootCAs:                     roots,
		AllowUnadvertisedRevocation: true,
		Experimental:                experimental.Transport{AllowHTTP: allowHTTP},
	}
	return policy, nil
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

// NewOID4VPRuntime builds a wallet for the sample flows. allowHTTP accepts the
// plain http endpoints of a local sample server through the experimental
// transport settings; it is not for production use.
func NewOID4VPRuntime(certPath string, allowHTTP bool) (*Runtime, error) {
	credStore, err := credstore.NewCredStoreDispatcher(credstore.WithDefaultConfig())
	if err != nil {
		return nil, err
	}

	receiverDispatcher, err := receiver.NewReceivingDispatcher(receiver.WithPlugin(receiverTypes.Oid4vci, &oid4vci.Oid4vciReceiver{
		Experimental: experimental.Transport{AllowHTTP: allowHTTP},
	}))
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
		// The sample verifier listens on plain http; that is outside
		// OpenID4VP and is opted into explicitly.
		Experimental: experimental.Presenter{Transport: experimental.Transport{AllowHTTP: allowHTTP}},
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

	issuerAcceptance, err := SampleIssuerAcceptance(os.Getenv("VCKNOTS_ISSUER_CA_PATH"), allowHTTP)
	if err != nil {
		return nil, err
	}

	w, err := wallet.NewWalletWithConfig(wallet.Config{
		CredentialAcceptance: issuerAcceptance,
		CredStore:            credStore,
		IDProfiler:           idProf,
		Receiver:             receiverDispatcher,
		Serializer:           serializerDispatcher,
		Verifier:             verifierDispatcher,
		Presenter:            presenterDispatcher,
		ClientAuth:           clientAuth,
		// Key is left unset so that NewWalletWithConfig generates a DPoP key
		// of its own. Reusing the registered client authentication key would
		// tie DPoP key rotation to the client assertion key.
		DPoP: wallet.DPoPConfig{Enabled: true},
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

// PresentAll answers the OpenID4VP request at uri with the credentials the
// wallet selects for it, through ParsePresentationRequest, SelectCredentials
// and SubmitPresentation. It skips the holder's consent that a real wallet
// asks for between selecting and submitting, which the examples do not need.
// It returns the redirect_uri of the verifier's response, if any.
func PresentAll(ctx context.Context, w *wallet.Wallet, uri string, key wallet.IKeyEntry, options serializerTypes.SerializePresentationOptions) (string, error) {
	request, err := w.ParsePresentationRequest(ctx, uri)
	if err != nil {
		return "", err
	}
	selections, err := w.SelectCredentials(ctx, request)
	if err != nil {
		return "", err
	}
	result, err := w.SubmitPresentation(ctx, request, wallet.Presentation{Key: key, Credentials: selections, SerializeOptions: options})
	if err != nil {
		return "", err
	}
	return result.RedirectURI, nil
}
