// Package wallet provides a verifiable credential wallet implementation.
//
// This package implements the OpenID for Verifiable Credentials specifications,
// enabling applications to receive credentials from issuers (OID4VCI) and present
// them to verifiers (OID4VP). It supports multiple credential formats including
// JWT-VC and SD-JWT-VC.
//
// The methods of Wallet run OpenID4VCI 1.0 and OpenID4VP 1.0 in stages, and
// the draft versions are reached through Wallet.Draft13 and Wallet.Draft24.
// Receiving a credential under a Pre-Authorized Code offer:
//
//	w, err := wallet.NewWalletWithConfig(wallet.Config{CredentialAcceptance: policy})
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	offer, err := w.ResolveCredentialOffer(ctx, offerURL)
//	if err != nil {
//		log.Fatal(err)
//	}
//	grant, err := w.AuthorizePreAuthorizedIssuance(ctx, wallet.PreAuthorizedIssuanceRequest{CredentialOffer: offer})
//	if err != nil {
//		log.Fatal(err)
//	}
//	result, err := w.RequestCredential(ctx, grant, wallet.CredentialRequest{HolderKeys: []wallet.IKeyEntry{holderKey}})
//	if err != nil {
//		log.Fatal(err)
//	}
//
// Presenting credentials, with the holder's consent between the selection and
// the submission:
//
//	request, err := w.ParsePresentationRequest(ctx, requestURI)
//	if err != nil {
//		log.Fatal(err)
//	}
//	selections, err := w.SelectCredentials(ctx, request)
//	if err != nil {
//		log.Fatal(err)
//	}
//	submitted, err := w.SubmitPresentation(ctx, request, wallet.Presentation{Key: holderKey, Credentials: selections})
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
	"github.com/trustknots/vcknots/wallet/experimental"
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
// Its methods are the stages of the protocols, and a caller runs them in
// order, keeping the state each returns (see IssuanceGrant and
// oid4vp.AdmittedRequest):
//   - OpenID4VCI 1.0: ResolveCredentialOffer, then BeginIssuance and
//     AuthorizeIssuance, or AuthorizePreAuthorizedIssuance, then
//     RequestCredential, RequestDeferredCredential and NotifyIssuer.
//   - OpenID4VP 1.0: ParsePresentationRequest (or ParseDCAPIRequest), then
//     SelectCredentials, and SubmitPresentation or DeclinePresentation after
//     the holder's consent.
//   - OpenID4VCI Draft 13: the issuance stages under Draft13. OpenID4VP
//     Draft 24: a request parsed under Draft24, then selected and submitted
//     as above. Config.Profiles enables each draft.
//
// The stages delegate to the dispatchers of Config: the ReceivingDispatcher
// and the PresentationDispatcher run the protocols, the
// SerializationDispatcher and the VerificationDispatcher parse and verify
// credentials, the CredStoreDispatcher stores them and the
// IdentityProfileDispatcher manages DIDs.
type Wallet struct {
	credStore  *credstore.CredStoreDispatcher
	idProf     *idprof.IdentityProfileDispatcher
	receiver   *receiver.ReceivingDispatcher
	serializer *serializer.SerializationDispatcher
	verifier   *verifier.VerificationDispatcher
	presenter  *presenter.PresentationDispatcher

	dpop       DPoPConfig
	clientAuth ClientAuthConfig

	// profile is the OpenID4VCI 1.0 / OpenID4VP 1.0 profile this wallet
	// enforces. Every protocol plugin the wallet uses reports the same
	// profile (see Config.Profiles).
	profile profile.Profile
	// draft13 and draft24 record whether Config.Profiles enables
	// profile.Draft13 and profile.Draft24.
	draft13 bool
	draft24 bool

	issuance IssuanceConfig
	// attestationConfig is a pointer so that Wallet stays comparable.
	attestationConfig *AttestationConfig
	// testHooks is nil unless Config.Experimental.Hooks sets a hook.
	testHooks *experimental.Hooks

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

	// Profiles selects the protocol profiles the wallet runs: exactly one
	// OpenID4VCI 1.0 / OpenID4VP 1.0 profile (profile.Final, profile.HAIP,
	// or either strengthened with Profile.With), and any of the draft
	// profiles profile.Draft13 and profile.Draft24, which enable
	// Wallet.Draft13 and Wallet.Draft24. Without a draft profile, its entry
	// points return ErrProfileForbidsDraft. A 1.0 profile with
	// Options.ForbidDraftProfiles (HAIP 1.0 profiles only the 1.0
	// specifications) refuses a draft profile beside it
	// (ErrProfileForbidsDraft); a second 1.0 profile, a repeated draft
	// profile or no 1.0 profile is ErrInvalidArgument.
	//
	// Every plugin of Receiver and Presenter that implements profile.Carrier
	// must report the 1.0 profile (ErrProfileMismatch). When that profile
	// carries any option, a plugin that does not implement profile.Carrier
	// is refused (ErrProfilePluginUnsupported), since it would not apply
	// them.
	//
	// An empty Profiles is DefaultProfiles(): Final with both draft profiles.
	// That is what the library ran before profiles could be chosen, so a
	// zero Config keeps every entry point an existing integration calls.
	Profiles []profile.Profile

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

	// Experimental carries the settings that depart from the OpenID4VC
	// specifications: plain http endpoints and rewrites of draft protocol
	// messages. Not specification-conforming; for testing only. The zero
	// value conforms. See package experimental.
	Experimental experimental.Options
}

// DPoPConfig holds configuration for DPoP proof generation. Key is the
// wallet's DPoP key; OpenID4VCI 1.0 issuances send a DPoP proof whenever it is
// set, and HAIP requires it. Enabled generates a key when Key is nil and
// forces DPoP on the Draft 13 token requests, which otherwise send it only to
// an authorization server that advertises dpop_signing_alg_values_supported.
type DPoPConfig struct {
	Enabled bool
	Key     IKeyEntry
}

// ClientAuthConfig holds configuration for client authentication at the
// authorization server's token endpoint.
//
// Method selects the authentication method. An empty value defaults to None and
// is never promoted. For an OpenID4VCI 1.0 pre-authorized_code token request
// without a client attestation, it must appear in the server's
// token_endpoint_auth_methods_supported, which RFC 8414 section 2 makes
// client_secret_basic when absent. A server that omits the list but declares
// pre-authorized_grant_anonymous_access_supported true takes an anonymous None
// request instead (OID4VCI 1.0 6.1 and 12.3).
//
// ClientID is optional for None on that request, and is sent unless
// pre-authorized_grant_anonymous_access_supported is true (OID4VCI 1.0 12.3).
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
	// instance (OpenID4VCI 1.0 Appendix E). It is asked for an attestation
	// of the Client Instance Key of each flow (attestation.ClientRequest).
	Client attestation.ClientProvider
	// ClientKey is the Client Instance Key the Client Attestation binds and
	// the PoP is signed with, for every authorization server. Using one key
	// for every server lets the servers correlate the instance
	// (draft-ietf-oauth-attestation-based-client-auth Section 11.1).
	//
	// When ClientKey is nil and ClientKeyFromDPoP is false, the wallet
	// generates an ephemeral P-256 key for each authorization server flow,
	// which that section RECOMMENDS: a Pre-Authorized Code token request
	// uses a key of its own, and an Authorization Code Flow carries the key
	// of its Pushed Authorization Request to its token request in
	// IssuanceAuthorization.ClientInstanceKey.
	ClientKey IKeyEntry
	// ClientKeyFromDPoP uses Config.DPoP.Key as the Client Instance Key, so
	// the DPoP key is attested. It is an opt-in: the one key then links the
	// instance across authorization servers and ties the attestation to the
	// DPoP key's lifetime. It cannot be combined with ClientKey.
	ClientKeyFromDPoP bool
	// Key supplies key attestations (OpenID4VCI 1.0 Appendix D).
	Key attestation.KeyProvider
	// Trust authenticates the attestations Client and Key return.
	Trust attestation.TrustPolicy
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

// NewWallet creates a Wallet with the default dispatchers, as
// NewWalletWithConfig does for a zero Config:
//   - Credential storage using the local file system
//   - OpenID4VCI for credential receiving
//   - OpenID4VP for credential presentation
//   - JWT VC, SD-JWT VC and Data Integrity credential serialization
//   - Signature verification for every algorithm the verifier package
//     registers by default
//   - did:key and did:jwk identity profiles
//
// The Config.Profiles of a zero Config apply: OpenID4VCI 1.0 and OpenID4VP
// 1.0 under profile.Final, with both draft profiles. The wallet has no
// Config.CredentialAcceptance, so receiving a credential needs an acceptance
// policy on the request that starts each issuance (IssuanceRequest.Acceptance
// or PreAuthorizedIssuanceRequest.Acceptance); without one no issuance starts
// (ErrCredentialAcceptancePolicyRequired). A wallet that receives credentials
// usually sets Config.CredentialAcceptance through NewWalletWithConfig
// instead.
//
// Returns an error if any dispatcher initialization fails.
func NewWallet() (*Wallet, error) {
	return NewWalletWithConfig(Config{})
}

// NewWalletWithConfig creates a Wallet from config: its protocol profiles, its
// credential acceptance policy, its OpenID4VCI client settings and any
// dispatcher it injects. A dispatcher field left nil is initialized with the
// default implementation; the default receiver and presenter are built for
// the OpenID4VCI 1.0 / OpenID4VP 1.0 profile of config.Profiles.
//
// An injected Receiver or Presenter is checked here, once: its plugins must
// report the wallet's profile (see Config.Profiles), and a refused dispatcher
// fails the constructor rather than a later method.
func NewWalletWithConfig(config Config) (*Wallet, error) {
	w, err := newWallet(config)
	return w, classify(err)
}

func newWallet(config Config) (*Wallet, error) {
	if err := validateClientAuthConfig(config.ClientAuth); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidArgument, err)
	}
	profiles, err := resolveProfiles(config.Profiles)
	if err != nil {
		return nil, err
	}
	walletProfile := profiles.final
	if err := checkExperimental(config, profiles); err != nil {
		return nil, err
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
		receiver, err := newDefaultReceiver(walletProfile, config.Experimental.Transport)
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
			Profile:                       walletProfile,
			SupportedTransactionDataTypes: slices.Clone(config.SupportedTransactionDataTypes),
			Experimental:                  experimental.Presenter{Transport: config.Experimental.Transport},
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
	if config.Attestation.ClientKeyFromDPoP && (config.Attestation.ClientKey != nil || config.DPoP.Key == nil) {
		return nil, fmt.Errorf("%w: Attestation.ClientKeyFromDPoP needs a DPoP key and no Attestation.ClientKey", ErrInvalidArgument)
	}
	attestationConfig := config.Attestation
	var testHooks *experimental.Hooks
	if config.Experimental.Hooks.Set() {
		hooks := config.Experimental.Hooks
		testHooks = &hooks
	}
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
		draft13: profiles.draft13,
		draft24: profiles.draft24,

		issuance:          config.Issuance,
		attestationConfig: &attestationConfig,
		testHooks:         testHooks,

		credentialAcceptance: config.CredentialAcceptance,
	}, nil
}

// newDefaultReceiver builds the receiver of a wallet whose Config.Receiver is
// nil: the upstream defaults under plain Final without experimental transport
// settings, and otherwise only an OpenID4VCI plugin constructed with the
// wallet's profile and transport.
func newDefaultReceiver(walletProfile profile.Profile, transport experimental.Transport) (*receiver.ReceivingDispatcher, error) {
	if walletProfile == profile.Final() && transport == (experimental.Transport{}) {
		return receiver.NewReceivingDispatcher(receiver.WithDefaultConfig())
	}
	return receiver.NewReceivingDispatcher(receiver.WithPlugin(receiverTypes.Oid4vci, &receiverOid4vci.Oid4vciReceiver{
		Experimental: transport,
		Profile:      walletProfile,
	}))
}

// checkExperimental refuses Config.Experimental settings the wallet could not
// apply or its profiles forbid: any of them under Options.ForbidExperimental,
// hooks without a draft profile (they rewrite draft messages only), and a
// transport escape with an injected plugin, which the wallet does not
// reconfigure.
func checkExperimental(config Config, profiles walletProfiles) error {
	hooks := config.Experimental.Hooks.Set()
	transport := config.Experimental.Transport != (experimental.Transport{})
	if !hooks && !transport {
		return nil
	}
	if profiles.final.Options().ForbidExperimental {
		return fmt.Errorf("%w: %w does not permit Config.Experimental", ErrInvalidArgument, profile.Refused("ForbidExperimental"))
	}
	if hooks && !profiles.draft13 && !profiles.draft24 {
		return fmt.Errorf("%w: Experimental.Hooks rewrite draft messages and no draft profile is enabled", ErrProfileForbidsDraft)
	}
	if !transport {
		return nil
	}
	if config.Receiver != nil || config.Presenter != nil {
		return fmt.Errorf("%w: Experimental.Transport configures only the plugins the wallet builds; set it on the injected plugin", ErrInvalidArgument)
	}
	return nil
}

// profileValidator is implemented by a plugin that can tell whether its own
// settings satisfy its profile, such as an experimental transport a profile
// with ForbidExperimental refuses.
type profileValidator interface {
	ValidateProfile() error
}

// checkPluginProfiles refuses a plugin whose profile.Carrier reports another
// profile than the wallet's and, when the wallet's profile carries options, a
// plugin that is not a Carrier: an option adds checks a plugin must know to
// apply. A plugin whose own settings its profile refuses (profileValidator)
// is refused too, so an injected plugin is held to the rules of one the
// wallet builds.
func checkPluginProfiles[P any](plugins []P, walletProfile profile.Profile) error {
	for _, plugin := range plugins {
		if validator, ok := any(plugin).(profileValidator); ok {
			if err := validator.ValidateProfile(); err != nil {
				return fmt.Errorf("%T: %w", plugin, err)
			}
		}
		carrier, ok := any(plugin).(profile.Carrier)
		if !ok {
			if walletProfile.Options() != (profile.Options{}) {
				return fmt.Errorf("%w: %T does not implement profile.Carrier", ErrProfilePluginUnsupported, plugin)
			}
			continue
		}
		pluginProfile := carrier.ProtocolProfile()
		if err := pluginProfile.RequireFinalVersion(); err != nil {
			return fmt.Errorf("%T: %w", plugin, err)
		}
		if pluginProfile != walletProfile {
			return fmt.Errorf("%w: %T enforces %s, the wallet %s", ErrProfileMismatch, plugin, pluginProfile, walletProfile)
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
