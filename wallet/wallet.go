// Package wallet provides a verifiable credential wallet implementation.
//
// This package implements the OpenID for Verifiable Credentials specifications,
// enabling applications to receive credentials from issuers (OID4VCI) and present
// them to verifiers (OID4VP). It supports multiple credential formats including
// JWT-VC and SD-JWT-VC.
//
// Basic usage:
//
//	w, err := wallet.NewWallet()
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	credential, err := w.ReceiveCredential(req)
//	if err != nil {
//		log.Fatal(err)
//	}
package wallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/acceptance"
	"github.com/trustknots/vcknots/wallet/attestation"
	"github.com/trustknots/vcknots/wallet/common"
	joseutil "github.com/trustknots/vcknots/wallet/common/jose"
	"github.com/trustknots/vcknots/wallet/credstore"
	"github.com/trustknots/vcknots/wallet/env"
	"github.com/trustknots/vcknots/wallet/idprof"
	idprofTypes "github.com/trustknots/vcknots/wallet/idprof/types"
	"github.com/trustknots/vcknots/wallet/presenter"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	"github.com/trustknots/vcknots/wallet/profile"
	"github.com/trustknots/vcknots/wallet/receiver"
	receiverOid4vci "github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
	"github.com/trustknots/vcknots/wallet/serializer"
	"github.com/trustknots/vcknots/wallet/verifier"
)

// Wallet implements high-level wallet operations for verifiable credentials.
//
// It coordinates multiple dispatcher components to execute complete workflows:
//   - ReceivingDispatcher: handles credential issuance protocols (e.g., OID4VCI)
//   - PresentationDispatcher: handles credential presentation protocols (e.g., OID4VP)
//   - SerializationDispatcher: handles credential serialization (JWT, SD-JWT)
//   - CredStoreDispatcher: manages credential storage
//   - IdentityProfileDispatcher: manages DIDs and identity profiles
//   - VerificationDispatcher: handles cryptographic signature verification
//
// Each workflow method (ReceiveCredential, PresentCredential) orchestrates
// multiple dispatchers to implement the complete protocol flow.
type Wallet struct {
	credStore  *credstore.CredStoreDispatcher
	idProf     *idprof.IdentityProfileDispatcher
	receiver   receivingDispatcher
	serializer *serializer.SerializationDispatcher
	verifier   *verifier.VerificationDispatcher
	presenter  *presenter.PresentationDispatcher

	dpop       DPoPConfig
	clientAuth ClientAuthConfig

	// profile is the policy this wallet enforces. Every protocol plugin the
	// wallet uses reports the same profile (see Config.Profile).
	profile profile.Profile

	issuance IssuanceConfig
	// attestationConfig is a pointer so that Wallet stays comparable.
	attestationConfig *AttestationConfig
	testHooks         *TestHooks

	credentialAcceptance *acceptance.Policy
}

// Config specifies the dispatcher components used by a Wallet.
//
// Each field represents an infrastructure component responsible for a specific
// aspect of wallet functionality. All fields are optional; if nil, a default
// implementation will be created automatically.
//
// This configuration is primarily used for dependency injection in testing
// or when custom plugin implementations are required. The wallet never
// modifies a dispatcher or plugin it is given, and the plugins' fields must
// not change after they are registered.
type Config struct {
	CredStore  *credstore.CredStoreDispatcher
	IDProfiler *idprof.IdentityProfileDispatcher
	Receiver   *receiver.ReceivingDispatcher
	Serializer *serializer.SerializationDispatcher
	Verifier   *verifier.VerificationDispatcher
	// Presenter's OpenID4VP plugin must be an *oid4vp.Oid4vpPresenter,
	// because the presentation methods take and return its
	// *oid4vp.AdmittedRequest handles; any other plugin is refused
	// (ErrInvalidArgument).
	Presenter *presenter.PresentationDispatcher

	DPoP       DPoPConfig
	ClientAuth ClientAuthConfig

	// Profile selects the protocol policy; the zero value is profile.Final.
	// Every plugin of Receiver and Presenter that implements profile.Carrier
	// must report this profile (ErrProfileMismatch). Under profile.HAIP a
	// plugin that does not implement profile.Carrier is refused
	// (ErrProfilePluginUnsupported), and so is TestHooks
	// (ErrProfileForbidsDraft).
	Profile profile.Profile

	// SupportedTransactionDataTypes lists the OpenID4VP transaction_data
	// "type" values the wallet can process (OpenID4VP 1.0 Section 5.1). It
	// configures the presenter the wallet builds when Presenter is nil; with
	// an injected Presenter, set it on the plugin instead.
	SupportedTransactionDataTypes []string

	// CredentialAcceptance configures the minimum credential verification rules
	// applied before a received credential is stored.
	CredentialAcceptance *acceptance.Policy

	// Storeless builds a wallet with no credential store, for a caller that
	// keeps credentials elsewhere. Received credentials are returned and not
	// stored, and a presentation takes its credentials by value. CredStore
	// must be nil; every operation that needs the store returns
	// ErrNoCredentialStore.
	Storeless bool

	// Issuance holds the wallet-level OpenID4VCI settings.
	Issuance IssuanceConfig

	// Attestation supplies and authenticates client and key attestations.
	Attestation AttestationConfig

	// TestHooks rewrites protocol messages the library built, for testing how
	// a peer handles them. Nil leaves every message as built.
	TestHooks *TestHooks
}

// DPoPConfig holds configuration for DPoP proof generation. Key is the
// wallet's DPoP key; OpenID4VCI 1.0 issuances send a DPoP proof whenever it is
// set, and HAIP requires it. Enabled generates a key when Key is nil and
// forces DPoP on the Draft 13 and ReceiveCredential paths.
type DPoPConfig struct {
	Enabled bool
	Key     IKeyEntry
}

// ClientAuthConfig holds configuration for client authentication at the
// authorization server's token endpoint.
//
// Method selects the authentication method. An empty value defaults to None,
// so private_key_jwt is only used when explicitly configured.
//
// ClientID and Key are required to use PrivateKeyJwt. Key must be the private
// key whose corresponding public key is registered with the authorization
// server (as JWKS).
//
// AssertionAudience is the authorization server identifier placed in the
// client_assertion aud claim. When empty, the authorization server metadata
// issuer is used, falling back to the token endpoint URL when issuer is absent.
//
// SigningAlg selects the JWS algorithm used to sign the client_assertion. It
// corresponds to the token_endpoint_auth_signing_alg client metadata value
// defined by OpenID Connect Dynamic Client Registration 1.0, and must be one
// of ES256, ES384 or ES512. An empty value defaults to ES256.
type ClientAuthConfig struct {
	Method            receiverTypes.TokenEndpointAuthMethod
	ClientID          string
	Key               IKeyEntry
	AssertionAudience string
	SigningAlg        jose.SignatureAlgorithm
}

// IssuanceConfig holds the wallet-level OpenID4VCI settings every issuance
// shares.
type IssuanceConfig struct {
	// RedirectURI is the redirect_uri of the Authorization Code Flow
	// (OpenID4VCI 1.0 Section 5.1).
	RedirectURI string
	// CredentialEncryption is the holder's policy for Credential Request and
	// Credential Response encryption (Section 10).
	CredentialEncryption CredentialEncryptionPolicy
}

// AttestationConfig supplies the attestations an issuance presents and the
// policy that authenticates them before they are sent. An attestation the
// wallet cannot authenticate is refused, not forwarded; a remote provider
// without x5c needs Trust.ResolveKey.
type AttestationConfig struct {
	// Client supplies the OAuth 2.0 Client Attestation of this wallet
	// instance (OpenID4VCI 1.0 Appendix E).
	Client attestation.ClientProvider
	// ClientKey is the wallet instance key the Client Attestation binds and
	// the PoP is signed with. Nil means DPoP.Key.
	ClientKey IKeyEntry
	// Key supplies key attestations (OpenID4VCI 1.0 Appendix D).
	Key attestation.KeyProvider
	// Trust authenticates the attestations Client and Key return.
	Trust attestation.TrustPolicy
}

// TestHooks rewrite messages after the library built them, so a tester can
// see how an issuer or verifier handles a malformed one. A nil hook leaves its
// message unchanged. They are refused under the HAIP profile.
type TestHooks struct {
	// KeyProof rewrites Draft 13 key proofs.
	KeyProof ProofTransform
	// PresentationExchangeResponse rewrites Draft 24 Presentation Exchange
	// responses.
	PresentationExchangeResponse Draft24ResponseTransform
}

// attestationSettings returns Config.Attestation, or its zero value for a
// Wallet built without NewWalletWithConfig.
func (w *Wallet) attestationSettings() AttestationConfig {
	if w.attestationConfig == nil {
		return AttestationConfig{}
	}
	return *w.attestationConfig
}

// signatureAlgorithm returns the configured client_assertion signing
// algorithm, defaulting to ES256 when unset.
func (c ClientAuthConfig) signatureAlgorithm() jose.SignatureAlgorithm {
	if c.SigningAlg == "" {
		return jose.ES256
	}
	return c.SigningAlg
}

// clientAuthenticationConfigured reports whether an OAuth2 client
// authentication mechanism is configured. An empty method defaults to none.
func clientAuthenticationConfigured(c ClientAuthConfig) bool {
	method := c.Method
	if method == "" {
		method = receiverTypes.None
	}
	return method != receiverTypes.None
}

// curveForSignatureAlgorithm returns the elliptic curve that alg requires.
// RFC 7518 section 3.4 pairs each ECDSA algorithm with exactly one curve, so
// the signing key must sit on the curve named here.
func curveForSignatureAlgorithm(alg jose.SignatureAlgorithm) (elliptic.Curve, error) {
	switch alg {
	case jose.ES256:
		return elliptic.P256(), nil
	case jose.ES384:
		return elliptic.P384(), nil
	case jose.ES512:
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported client authentication signing algorithm: %q", alg)
	}
}

// NewWallet creates a Wallet with default dispatcher configurations.
//
// This initializes all dispatcher components with their built-in plugin implementations:
//   - Credential storage using local file system
//   - OID4VCI for credential receiving
//   - OID4VP for credential presentation
//   - JWT and SD-JWT serialization support
//   - ES256 signature verification
//   - DID:key and DID:jwk identity profiles
//
// Returns an error if any dispatcher initialization fails.
func NewWallet() (*Wallet, error) {
	return NewWalletWithConfig(Config{})
}

// NewWalletWithConfig creates a Wallet with custom dispatcher configurations.
//
// This allows injection of custom dispatcher implementations or configurations.
// Any dispatcher field left nil in the config will be initialized with a default
// implementation automatically.
//
// This constructor is primarily used when:
//   - Testing with mock dispatchers
//   - Registering custom protocol plugins
//   - Using non-default storage backends
//
// For typical usage, prefer NewWallet instead.
func NewWalletWithConfig(config Config) (*Wallet, error) {
	w, err := newWallet(config)
	return w, classify(err)
}

func newWallet(config Config) (*Wallet, error) {
	if err := validateClientAuthConfig(config.ClientAuth); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidArgument, err)
	}
	walletProfile, err := config.Profile.Normalize()
	if err != nil {
		return nil, fmt.Errorf("invalid wallet profile: %w", err)
	}
	if walletProfile.IsHAIP() && config.TestHooks != nil {
		return nil, fmt.Errorf("%w: TestHooks are refused under HAIP", ErrProfileForbidsDraft)
	}
	if config.Storeless && config.CredStore != nil {
		return nil, fmt.Errorf("%w: a storeless wallet cannot be configured with a credential store", ErrInvalidArgument)
	}
	if config.Presenter != nil && len(config.SupportedTransactionDataTypes) > 0 {
		return nil, fmt.Errorf("%w: SupportedTransactionDataTypes configures only the default presenter; set it on the injected presenter plugin", ErrInvalidArgument)
	}

	if config.CredStore == nil && !config.Storeless {
		credStore, err := credstore.NewCredStoreDispatcher(credstore.WithDefaultConfig())
		if err != nil {
			return nil, fmt.Errorf("failed to create default credential store: %w", err)
		}
		config.CredStore = credStore
	}

	if config.IDProfiler == nil {
		idProf, err := idprof.NewIdentityProfileDispatcher(idprof.WithDefaultConfig())
		if err != nil {
			return nil, fmt.Errorf("failed to create default identity profiler: %w", err)
		}
		config.IDProfiler = idProf
	}

	if config.Receiver == nil {
		receiver, err := newDefaultReceiver(walletProfile)
		if err != nil {
			return nil, fmt.Errorf("failed to create default receiver: %w", err)
		}
		config.Receiver = receiver
	}

	if config.Serializer == nil {
		serializer, err := serializer.NewSerializationDispatcher(serializer.WithDefaultConfig())
		if err != nil {
			return nil, fmt.Errorf("failed to create default serializer: %w", err)
		}
		config.Serializer = serializer
	}

	if config.Verifier == nil {
		verifier, err := verifier.NewVerificationDispatcher(verifier.WithDefaultConfig())
		if err != nil {
			return nil, fmt.Errorf("failed to create default verifier: %w", err)
		}
		config.Verifier = verifier
	}

	if config.Presenter == nil {
		presenter, err := presenter.NewPresentationDispatcher(presenter.WithPlugin(presenter.Oid4vp, &oid4vp.Oid4vpPresenter{
			AllowHTTP:                     env.IsHTTPAllowed(),
			Profile:                       walletProfile,
			SupportedTransactionDataTypes: slices.Clone(config.SupportedTransactionDataTypes),
		}))
		if err != nil {
			return nil, fmt.Errorf("failed to create default presenter: %w", err)
		}
		config.Presenter = presenter
	}

	if err := checkPluginProfiles(config.Receiver.Plugins(), walletProfile); err != nil {
		return nil, fmt.Errorf("receiver: %w", err)
	}
	if err := checkPluginProfiles(config.Presenter.Plugins(), walletProfile); err != nil {
		return nil, fmt.Errorf("presenter: %w", err)
	}
	if err := checkBundledPresenter(config.Presenter); err != nil {
		return nil, err
	}

	if config.DPoP.Enabled && config.DPoP.Key == nil {
		key, err := newInMemoryECKeyEntry()
		if err != nil {
			return nil, fmt.Errorf("failed to generate DPoP key: %w", err)
		}
		config.DPoP.Key = key
	}
	attestationConfig := config.Attestation
	return &Wallet{
		credStore:  config.CredStore,
		idProf:     config.IDProfiler,
		receiver:   config.Receiver,
		serializer: config.Serializer,
		verifier:   config.Verifier,
		presenter:  config.Presenter,
		dpop:       config.DPoP,
		clientAuth: config.ClientAuth,

		profile: walletProfile,

		issuance:          config.Issuance,
		attestationConfig: &attestationConfig,
		testHooks:         config.TestHooks,

		credentialAcceptance: config.CredentialAcceptance,
	}, nil
}

// newDefaultReceiver builds the receiver of a wallet whose Config.Receiver is
// nil: the upstream defaults under Final, and only an OpenID4VCI plugin
// constructed with the HAIP profile under HAIP.
func newDefaultReceiver(walletProfile profile.Profile) (*receiver.ReceivingDispatcher, error) {
	if !walletProfile.IsHAIP() {
		return receiver.NewReceivingDispatcher(receiver.WithDefaultConfig())
	}
	return receiver.NewReceivingDispatcher(receiver.WithPlugin(receiverTypes.Oid4vci, &receiverOid4vci.Oid4vciReceiver{
		AllowHTTP: env.IsHTTPAllowed(),
		Profile:   walletProfile,
	}))
}

// checkPluginProfiles refuses a plugin whose profile.Carrier reports another
// profile than the wallet's and, under HAIP, a plugin that is not a Carrier:
// HAIP adds checks a plugin must know to apply.
func checkPluginProfiles[P any](plugins []P, walletProfile profile.Profile) error {
	for _, plugin := range plugins {
		carrier, ok := any(plugin).(profile.Carrier)
		if !ok {
			if walletProfile.IsHAIP() {
				return fmt.Errorf("%w: %T does not implement profile.Carrier", ErrProfilePluginUnsupported, plugin)
			}
			continue
		}
		pluginProfile, err := carrier.ProtocolProfile().Normalize()
		if err != nil {
			return fmt.Errorf("%T: %w", plugin, err)
		}
		if pluginProfile != walletProfile {
			return fmt.Errorf("%w: %T enforces %q, the wallet %q", ErrProfileMismatch, plugin, pluginProfile, walletProfile)
		}
	}
	return nil
}

func validateClientAuthConfig(config ClientAuthConfig) error {
	method := config.Method
	if method == "" {
		method = receiverTypes.None
	}

	switch method {
	case receiverTypes.None:
		return nil
	case receiverTypes.PrivateKeyJwt:
		if strings.TrimSpace(config.ClientID) == "" {
			return fmt.Errorf("client ID is required for private_key_jwt client authentication")
		}
		if config.Key == nil {
			return fmt.Errorf("client authentication key is required for private_key_jwt client authentication")
		}
		if strings.TrimSpace(config.Key.PublicKey().KeyID) == "" {
			return fmt.Errorf("client authentication key kid is required for private_key_jwt client authentication")
		}
		alg := config.signatureAlgorithm()
		curve, err := curveForSignatureAlgorithm(alg)
		if err != nil {
			return err
		}
		if _, err := joseutil.NewJWKSigner(config.Key, alg); err != nil {
			return fmt.Errorf("client authentication key is not compatible with %s: %w", alg, err)
		}
		var publicKey *ecdsa.PublicKey

		switch k := config.Key.PublicKey().Key.(type) {
		case *ecdsa.PublicKey:
			publicKey = k
		case ecdsa.PublicKey:
			publicKey = &k
		}

		if publicKey == nil || publicKey.Curve == nil || publicKey.Params() == nil ||
			publicKey.Params().Name != curve.Params().Name {
			return fmt.Errorf("client authentication key is not compatible with %s", alg)
		}
		return nil
	default:
		return fmt.Errorf("unsupported client authentication method: %q", method)
	}
}

// checkBundledPresenter refuses a presenter plugin other than the bundled
// *oid4vp.Oid4vpPresenter: the presentation methods answer the
// *oid4vp.AdmittedRequest handles only that plugin admits.
func checkBundledPresenter(d *presenter.PresentationDispatcher) error {
	for _, plugin := range d.Plugins() {
		if _, ok := plugin.(*oid4vp.Oid4vpPresenter); !ok {
			return fmt.Errorf("%w: the OpenID4VP presenter plugin must be an *oid4vp.Oid4vpPresenter, got %T", ErrInvalidArgument, plugin)
		}
	}
	return nil
}

// SetReceiver replaces the receiver dispatcher after checking its plugins as
// NewWalletWithConfig does. A refused dispatcher is not installed: every
// method that needs the receiver then returns the refusal, until a later
// SetReceiver succeeds.
//
// Deprecated: set Config.Receiver, which reports the refusal from
// NewWalletWithConfig.
func (w *Wallet) SetReceiver(r *receiver.ReceivingDispatcher) {
	if r == nil {
		w.receiver = refusedReceiver{err: fmt.Errorf("%w: SetReceiver got a nil dispatcher", ErrInvalidArgument)}
		return
	}
	if err := checkPluginProfiles(r.Plugins(), w.profile); err != nil {
		w.receiver = refusedReceiver{err: fmt.Errorf("SetReceiver: %w", err)}
		return
	}
	w.receiver = r
}

// receivingDispatcher is the part of *receiver.ReceivingDispatcher the wallet
// uses, so a dispatcher SetReceiver refused can stand in as refusedReceiver.
type receivingDispatcher interface {
	Plugins() []receiverTypes.Receiver
	OID4VCITransport(receiverTypes.SupportedReceivingTypes) (receiverTypes.OID4VCITransport, error)
	Draft13Transport(receiverTypes.SupportedReceivingTypes) (receiverTypes.Draft13Transport, error)
	FetchIssuerMetadata(common.URIField, receiverTypes.SupportedReceivingTypes) (*receiverTypes.CredentialIssuerMetadata, error)
	FetchAuthorizationServerMetadata(common.URIField, receiverTypes.SupportedReceivingTypes) (*receiverTypes.AuthorizationServerMetadata, error)
	FetchAccessToken(receiverTypes.SupportedReceivingTypes, common.URIField, string, string, ...receiverTypes.TokenRequestOption) (*receiverTypes.CredentialIssuanceAccessToken, error)
	FetchNonce(receiverTypes.SupportedReceivingTypes, common.URIField) (*string, error)
	ReceiveCredential(receiverTypes.SupportedReceivingTypes, common.URIField, string, *string, receiverTypes.CredentialIssuanceAccessToken, *receiverTypes.CredentialDefinition, *string, ...*receiverTypes.CredentialRequestOptions) (*string, error)
}

var _ receivingDispatcher = (*receiver.ReceivingDispatcher)(nil)

// refusedReceiver answers every call with the error SetReceiver refused a
// dispatcher with.
type refusedReceiver struct{ err error }

func (r refusedReceiver) Plugins() []receiverTypes.Receiver { return nil }

func (r refusedReceiver) OID4VCITransport(receiverTypes.SupportedReceivingTypes) (receiverTypes.OID4VCITransport, error) {
	return nil, r.err
}

func (r refusedReceiver) Draft13Transport(receiverTypes.SupportedReceivingTypes) (receiverTypes.Draft13Transport, error) {
	return nil, r.err
}

func (r refusedReceiver) FetchIssuerMetadata(common.URIField, receiverTypes.SupportedReceivingTypes) (*receiverTypes.CredentialIssuerMetadata, error) {
	return nil, r.err
}

func (r refusedReceiver) FetchAuthorizationServerMetadata(common.URIField, receiverTypes.SupportedReceivingTypes) (*receiverTypes.AuthorizationServerMetadata, error) {
	return nil, r.err
}

func (r refusedReceiver) FetchAccessToken(receiverTypes.SupportedReceivingTypes, common.URIField, string, string, ...receiverTypes.TokenRequestOption) (*receiverTypes.CredentialIssuanceAccessToken, error) {
	return nil, r.err
}

func (r refusedReceiver) FetchNonce(receiverTypes.SupportedReceivingTypes, common.URIField) (*string, error) {
	return nil, r.err
}

func (r refusedReceiver) ReceiveCredential(receiverTypes.SupportedReceivingTypes, common.URIField, string, *string, receiverTypes.CredentialIssuanceAccessToken, *receiverTypes.CredentialDefinition, *string, ...*receiverTypes.CredentialRequestOptions) (*string, error) {
	return nil, r.err
}

// GenerateDID generates a DID from given options.
func (w *Wallet) GenerateDID(options DIDCreateOptions) (*idprofTypes.IdentityProfile, error) {
	parts := strings.SplitN(options.TypeID, ":", 2)
	if len(parts) != 2 || parts[0] != "did" {
		return nil, fmt.Errorf("%w: invalid DID type ID format: %s", ErrInvalidArgument, options.TypeID)
	}
	method := parts[1]

	createOption := func(config *idprofTypes.CreateConfig) error {
		config.Set("method", method)
		config.Set("publicKey", &options.PublicKey)
		return nil
	}

	identity, err := w.idProf.Create("did", createOption)
	if err != nil {
		// Creating a did:key or did:jwk is local, so a failure is a
		// method or key the caller chose that the plugins refuse.
		if _, coded := common.CodeOf(err); !coded {
			err = keepMessage(ErrInvalidArgument, err)
		}
		return nil, classify(err)
	}
	return identity, nil
}

// DIDCreateOptions holds options for DID creation.
type DIDCreateOptions struct {
	TypeID    string
	PublicKey jose.JSONWebKey
}

func randomBase64URL(size int) (string, error) {
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}
