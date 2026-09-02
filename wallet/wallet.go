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
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/trustknots/vcknots/wallet/common"
	joseutil "github.com/trustknots/vcknots/wallet/common/jose"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/credstore"
	"github.com/trustknots/vcknots/wallet/credstore/types"
	"github.com/trustknots/vcknots/wallet/env"
	"github.com/trustknots/vcknots/wallet/idprof"
	idprofTypes "github.com/trustknots/vcknots/wallet/idprof/types"
	"github.com/trustknots/vcknots/wallet/presenter"
	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp"
	presenterTypes "github.com/trustknots/vcknots/wallet/presenter/types"
	"github.com/trustknots/vcknots/wallet/receiver"
	receiverOid4vci "github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
	"github.com/trustknots/vcknots/wallet/serializer"
	sdjwtvc "github.com/trustknots/vcknots/wallet/serializer/plugins/sdjwtvc"
	serializerTypes "github.com/trustknots/vcknots/wallet/serializer/types"
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
	receiver   *receiver.ReceivingDispatcher
	serializer *serializer.SerializationDispatcher
	verifier   *verifier.VerificationDispatcher
	presenter  *presenter.PresentationDispatcher

	dpop       DPoPConfig
	clientAuth ClientAuthConfig
}

// Config specifies the dispatcher components used by a Wallet.
//
// Each field represents an infrastructure component responsible for a specific
// aspect of wallet functionality. All fields are optional; if nil, a default
// implementation will be created automatically.
//
// This configuration is primarily used for dependency injection in testing
// or when custom plugin implementations are required.
type Config struct {
	CredStore  *credstore.CredStoreDispatcher
	IDProfiler *idprof.IdentityProfileDispatcher
	Receiver   *receiver.ReceivingDispatcher
	Serializer *serializer.SerializationDispatcher
	Verifier   *verifier.VerificationDispatcher
	Presenter  *presenter.PresentationDispatcher

	DPoP       DPoPConfig
	ClientAuth ClientAuthConfig
}

// DPoPConfig holds configuration for DPoP proof generation.
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

// signatureAlgorithm returns the configured client_assertion signing
// algorithm, defaulting to ES256 when unset.
func (c ClientAuthConfig) signatureAlgorithm() jose.SignatureAlgorithm {
	if c.SigningAlg == "" {
		return jose.ES256
	}
	return c.SigningAlg
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

var dpopNonceHTTPClient = &http.Client{
	Timeout: 10 * time.Second,
}

const maxDPoPNonceResponseBodyBytes int64 = 4 << 10

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
	credStore, err := credstore.NewCredStoreDispatcher(credstore.WithDefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create credential store: %w", err)
	}

	receiver, err := receiver.NewReceivingDispatcher(receiver.WithDefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create receiver: %w", err)
	}

	serializer, err := serializer.NewSerializationDispatcher(serializer.WithDefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create serializer: %w", err)
	}

	verifier, err := verifier.NewVerificationDispatcher(verifier.WithDefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create verifier: %w", err)
	}

	presenter, err := presenter.NewPresentationDispatcher(presenter.WithDefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create presenter: %w", err)
	}

	idProf, err := idprof.NewIdentityProfileDispatcher(idprof.WithDefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create identity profiler: %w", err)
	}

	config := Config{
		CredStore:  credStore,
		IDProfiler: idProf,
		Receiver:   receiver,
		Serializer: serializer,
		Verifier:   verifier,
		Presenter:  presenter,
		DPoP:       DPoPConfig{},
		ClientAuth: ClientAuthConfig{},
	}

	return NewWalletWithConfig(config)
}

// NewWallet creates a Wallet with custom dispatcher configurations.
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
	if err := validateClientAuthConfig(config.ClientAuth); err != nil {
		return nil, err
	}

	if config.CredStore == nil {
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
		receiver, err := receiver.NewReceivingDispatcher(receiver.WithDefaultConfig())
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
		presenter, err := presenter.NewPresentationDispatcher(presenter.WithDefaultConfig())
		if err != nil {
			return nil, fmt.Errorf("failed to create default presenter: %w", err)
		}
		config.Presenter = presenter
	}

	if config.DPoP.Enabled && config.DPoP.Key == nil {
		key, err := newInMemoryECKeyEntry()
		if err != nil {
			return nil, fmt.Errorf("failed to generate DPoP key: %w", err)
		}
		config.DPoP.Key = key
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
	}, nil
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

// SetReceiver sets the receiver dispatcher.
func (w *Wallet) SetReceiver(r *receiver.ReceivingDispatcher) {
	w.receiver = r
}

// GenerateDID generates a DID from given options.
func (w *Wallet) GenerateDID(options DIDCreateOptions) (*idprofTypes.IdentityProfile, error) {
	parts := strings.SplitN(options.TypeID, ":", 2)
	if len(parts) != 2 || parts[0] != "did" {
		return nil, fmt.Errorf("invalid DID type ID format: %s", options.TypeID)
	}
	method := parts[1]

	createOption := func(config *idprofTypes.CreateConfig) error {
		config.Set("method", method)
		config.Set("publicKey", &options.PublicKey)
		return nil
	}

	return w.idProf.Create("did", createOption)
}

// VerifyCredential verifies a credential with a public key.
func (w *Wallet) VerifyCredential(credential *credential.Credential, pubKey jose.JSONWebKey) bool {
	if credential.Proof == nil {
		return false
	}

	result, err := w.verifier.Verify(credential.Proof, &pubKey)
	return err != nil && result
}

// DIDCreateOptions holds options for DID creation.
type DIDCreateOptions struct {
	TypeID    string
	PublicKey jose.JSONWebKey
}

// ReceiveCredentialRequest holds parameters for receiving a credential.
type ReceiveCredentialRequest struct {
	CredentialOffer      *CredentialOffer
	Type                 receiverTypes.SupportedReceivingTypes
	Key                  IKeyEntry
	RequestedFormat      credential.SupportedSerializationFlavor
	CachedIssuerMetadata *receiverTypes.CredentialIssuerMetadata
	TxCode               string
}

// CredentialOffer represents a credential offer from an issuer.
type CredentialOffer struct {
	CredentialIssuer           *url.URL                         `json:"credential_issuer"`
	CredentialConfigurationIDs []string                         `json:"credential_configuration_ids"`
	Grants                     map[string]*CredentialOfferGrant `json:"grants"`
}

// CredentialOfferGrant represents a grant in a credential offer.
type CredentialOfferGrant struct {
	PreAuthorizedCode string  `json:"pre-authorized_code"`
	TxCode            *TxCode `json:"tx_code,omitempty"`
}

type TxCode struct {
	InputMode   string `json:"input_mode,omitempty"`
	Length      int    `json:"length,omitempty"`
	Description string `json:"description,omitempty"`
}

// GetCredentialEntriesRequest holds parameters for querying credential entries.
type GetCredentialEntriesRequest struct {
	Offset int
	Limit  *int
	Filter func(*SavedCredential) bool
}

// SavedCredential represents a credential with its storage entry.
type SavedCredential struct {
	Credential *credential.Credential
	Entry      *types.CredentialEntry
}

// RedirectHandler is called when the verifier returns a redirect URI.
type RedirectHandler func(string) error

// PresentCredentialOptions configures presentation serialization and redirect handling.
type PresentCredentialOptions struct {
	SerializeOptions serializerTypes.SerializePresentationOptions
	OnRedirect       RedirectHandler
}

// IKeyEntry represents a key entry interface for signing operations.
// Sign signs the input bytes. ECDSA implementations may return either
// DER-encoded ASN.1 signatures or raw IEEE P1363 (R || S) signatures.
// Callers that require JWS-compatible ES256 signatures should prefer
// using JWKSigner, which normalizes DER-encoded signatures to IEEE P1363.
type IKeyEntry interface {
	ID() string
	PublicKey() jose.JSONWebKey
	Sign(data []byte) ([]byte, error)
}

type credentialRequestProofBindingMethod string

const (
	credentialRequestProofBindingMethodKID credentialRequestProofBindingMethod = "kid"
	credentialRequestProofBindingMethodJWK credentialRequestProofBindingMethod = "jwk"
)

func resolveCredentialRequestProofBindingMethod(
	credentialConfiguration *receiverTypes.CredentialConfiguration,
) credentialRequestProofBindingMethod {
	if credentialConfiguration == nil {
		return credentialRequestProofBindingMethodKID
	}

	format := strings.ToLower(strings.TrimSpace(credentialConfiguration.Format))
	if format == "jwt_vc_json" || format == "jwt_vc" {
		return credentialRequestProofBindingMethodKID
	}

	if credentialConfiguration.CryptographicBindingMethodsSupported == nil {
		return credentialRequestProofBindingMethodKID
	}

	for _, method := range *credentialConfiguration.CryptographicBindingMethodsSupported {
		normalized := strings.ToLower(strings.TrimSpace(method))
		if strings.HasPrefix(normalized, "did:") {
			return credentialRequestProofBindingMethodKID
		}

		if strings.EqualFold(strings.TrimSpace(method), string(credentialRequestProofBindingMethodJWK)) {
			return credentialRequestProofBindingMethodJWK
		}
	}

	return credentialRequestProofBindingMethodKID
}

type inMemoryECKeyEntry struct {
	id      string
	privKey *ecdsa.PrivateKey
	pubJWK  jose.JSONWebKey
}

type keyEntryWithoutPublicKeyID struct {
	IKeyEntry
}

func (k keyEntryWithoutPublicKeyID) PublicKey() jose.JSONWebKey {
	jwk := k.IKeyEntry.PublicKey()
	jwk.KeyID = ""
	return jwk
}

func newInMemoryECKeyEntry() (*inMemoryECKeyEntry, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
	}
	id := uuid.NewString()
	pubJWK := jose.JSONWebKey{
		Key:       &privKey.PublicKey,
		KeyID:     id,
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}
	return &inMemoryECKeyEntry{
		id:      id,
		privKey: privKey,
		pubJWK:  pubJWK,
	}, nil
}

func (k *inMemoryECKeyEntry) ID() string {
	return k.id
}

func (k *inMemoryECKeyEntry) PublicKey() jose.JSONWebKey {
	return k.pubJWK
}

func (k *inMemoryECKeyEntry) Sign(data []byte) ([]byte, error) {
	digest := sha256.Sum256(data)
	return ecdsa.SignASN1(rand.Reader, k.privKey, digest[:])
}

// convertEntryToSavedCredential converts a CredentialEntry to SavedCredential.
// Returns error if conversion fails (invalid flavor or deserialization error).
func (w *Wallet) convertEntryToSavedCredential(entry types.CredentialEntry) (*SavedCredential, error) {
	f, err := entry.SerializationFlavor()
	if err != nil {
		return nil, fmt.Errorf("invalid serialization flavor: %w", err)
	}

	cred, err := w.serializer.DeserializeCredential(f, entry.Raw)
	if err != nil {
		return nil, fmt.Errorf("deserialization failed: %w", err)
	}

	return &SavedCredential{
		Credential: cred,
		Entry:      &entry,
	}, nil
}

// generateJWTProof generates a JWT proof for credential requests.
// When clientID is nil, iss is omitted (anonymous pre-authorized flow).
// When clientID is provided, it must be non-empty.
func (w *Wallet) generateJWTProof(
	key IKeyEntry,
	did *idprofTypes.IdentityProfile,
	nonce *string,
	aud string,
	clientID *string,
	proofBindingMethod credentialRequestProofBindingMethod,
) (string, error) {
	signerOpts := (&jose.SignerOptions{}).WithType("openid4vci-proof+jwt")
	signingKeyEntry := key
	if proofBindingMethod == credentialRequestProofBindingMethodJWK {
		publicJWK := key.PublicKey()
		signerOpts = signerOpts.WithHeader("jwk", publicJWK.Public())
		signingKeyEntry = keyEntryWithoutPublicKeyID{IKeyEntry: key}
	} else {
		if did == nil {
			return "", fmt.Errorf("did is required for kid proof binding")
		}
		if strings.TrimSpace(did.ID) == "" {
			return "", fmt.Errorf("did.ID is required for kid proof binding")
		}
		signerOpts = signerOpts.WithHeader("kid", did.ID)
	}

	signerAdapter, err := joseutil.NewJWKSigner(signingKeyEntry, jose.ES256)
	if err != nil {
		return "", fmt.Errorf("failed to create JWT proof signer adapter: %w", err)
	}

	claims := map[string]interface{}{
		"iat": time.Now().Unix(),
		"aud": aud,
	}

	if clientID != nil {
		if strings.TrimSpace(*clientID) == "" {
			return "", fmt.Errorf("clientID must be non-empty when provided")
		}
		claims["iss"] = *clientID
	}

	if nonce != nil && *nonce != "" {
		claims["nonce"] = *nonce
	}

	signingKey := jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       signerAdapter,
	}

	signer, err := jose.NewSigner(signingKey, signerOpts)
	if err != nil {
		return "", fmt.Errorf("failed to create JWT proof signer: %w", err)
	}

	proof, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("failed to serialize JWT proof: %w", err)
	}

	return proof, nil
}

func (w *Wallet) generateDPoPProof(key IKeyEntry, method, targetURL, accessToken string, nonce *string) (string, error) {
	if key == nil {
		return "", fmt.Errorf("dpop key is required")
	}

	publicJWK := key.PublicKey()

	var pub *ecdsa.PublicKey

	switch k := publicJWK.Key.(type) {
	case *ecdsa.PublicKey:
		pub = k
	case ecdsa.PublicKey:
		pub = &k
	default:
		return "", fmt.Errorf("dpop key must be ECDSA public key")
	}

	if pub.Curve != elliptic.P256() {
		return "", fmt.Errorf("dpop key must use P-256 curve")
	}

	signerAdapter, err := joseutil.NewJWKSigner(key, jose.ES256)
	if err != nil {
		return "", fmt.Errorf("failed to create dpop signer adapter: %w", err)
	}

	signingKey := jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       signerAdapter,
	}

	signerOpts := (&jose.SignerOptions{}).WithType("dpop+jwt")

	publicOnlyJWK := jose.JSONWebKey{
		Key:       pub,
		KeyID:     publicJWK.KeyID,
		Algorithm: string(jose.ES256),
		Use:       publicJWK.Use,
	}

	signerOpts = signerOpts.WithHeader("jwk", publicOnlyJWK)

	signer, err := jose.NewSigner(signingKey, signerOpts)
	if err != nil {
		return "", fmt.Errorf("failed to create dpop signer: %w", err)
	}

	claims := map[string]any{
		"jti": uuid.NewString(),
		"htm": strings.ToUpper(method),
		"htu": targetURL,
		"iat": time.Now().Unix(),
	}

	if accessToken != "" {
		accessTokenHash := sha256.Sum256([]byte(accessToken))
		claims["ath"] = base64.RawURLEncoding.EncodeToString(accessTokenHash[:])
	}
	if nonce != nil && *nonce != "" {
		claims["nonce"] = *nonce
	}

	proof, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("failed to serialize dpop proof: %w", err)
	}

	return proof, nil
}

// generateClientAssertion builds a signed JWT used as the client_assertion
// parameter for private_key_jwt client authentication (RFC 7523).
//
// The resulting JWT contains the following claims: iss, sub (both equal to the
// client_id), aud (the resolved authorization server audience), iat, nbf, exp,
// and jti. The header carries the signing key's kid and the given alg.
func (w *Wallet) generateClientAssertion(key IKeyEntry, clientID, audience string, alg jose.SignatureAlgorithm) (string, error) {
	if key == nil {
		return "", fmt.Errorf("client auth key is required")
	}
	if strings.TrimSpace(clientID) == "" {
		return "", fmt.Errorf("clientID is required for client assertion")
	}
	if strings.TrimSpace(audience) == "" {
		return "", fmt.Errorf("audience is required for client assertion aud")
	}
	if _, err := curveForSignatureAlgorithm(alg); err != nil {
		return "", err
	}

	signerAdapter, err := joseutil.NewJWKSigner(key, alg)
	if err != nil {
		return "", fmt.Errorf("failed to create client assertion signer adapter: %w", err)
	}

	signerOpts := (&jose.SignerOptions{}).WithType("JWT")
	if kid := key.PublicKey().KeyID; strings.TrimSpace(kid) != "" {
		signerOpts = signerOpts.WithHeader("kid", kid)
	}

	signingKey := jose.SigningKey{
		Algorithm: alg,
		Key:       signerAdapter,
	}

	signer, err := jose.NewSigner(signingKey, signerOpts)
	if err != nil {
		return "", fmt.Errorf("failed to create client assertion signer: %w", err)
	}

	now := time.Now()
	claims := map[string]any{
		"iss": clientID,
		"sub": clientID,
		"aud": audience,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(clientAssertionLifetime).Unix(),
		"jti": uuid.NewString(),
	}

	assertion, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("failed to serialize client assertion: %w", err)
	}

	return assertion, nil
}

// clientAssertionLifetime is the validity window of a generated client_assertion.
const clientAssertionLifetime = 5 * time.Minute

// errNoUsableClientAuthMethod reports that neither anonymous access nor the
// configured client authentication method can be used at the token endpoint.
var errNoUsableClientAuthMethod = errors.New(
	"no usable client authentication method for the authorization server token endpoint; " +
		"the authorization server declares pre-authorized_grant_anonymous_access_supported as false, " +
		"or it does not support the configured client authentication method")

// resolveClientAuthMethod checks whether the configured client authentication
// method can be used at the authorization server token endpoint.
//
// An empty method defaults to anonymous authentication (None).
func resolveClientAuthMethod(clientAuth ClientAuthConfig, authMetadata *receiverTypes.AuthorizationServerMetadata) (receiverTypes.TokenEndpointAuthMethod, bool) {
	method := clientAuth.Method
	if method == "" {
		method = receiverTypes.None
	}
	return method, clientAuthMethodAvailable(method, clientAuth, authMetadata)
}

// clientAuthMethodAvailable reports whether the given method can be used against
// the authorization server described by authMetadata with the given config.
func clientAuthMethodAvailable(method receiverTypes.TokenEndpointAuthMethod, clientAuth ClientAuthConfig, authMetadata *receiverTypes.AuthorizationServerMetadata) bool {
	switch method {
	case receiverTypes.None:
		// pre-authorized_grant_anonymous_access_supported is an OPTIONAL
		// authorization server metadata parameter, so an absent value means
		// "unknown", not "unsupported". Issuers commonly omit it entirely — the
		// OpenID conformance suite among them — and treating that as a refusal
		// stops the pre-authorized code flow before a single token request goes
		// out. Only an explicit false states that the authorization server
		// rejects the grant without client authentication.
		if authMetadata == nil {
			return false
		}
		anonymousAccess := authMetadata.PreAuthorizedGrantAnonymousAccessSupported
		return anonymousAccess == nil || *anonymousAccess

	case receiverTypes.PrivateKeyJwt:
		if strings.TrimSpace(clientAuth.ClientID) == "" || clientAuth.Key == nil {
			return false
		}
		if !asMetadataSupportsAuthMethod(authMetadata, receiverTypes.PrivateKeyJwt) {
			return false
		}
		return asMetadataSupportsSigningAlg(authMetadata, clientAuth.signatureAlgorithm())
	}
	return false
}

func asMetadataSupportsAuthMethod(authMetadata *receiverTypes.AuthorizationServerMetadata, method receiverTypes.TokenEndpointAuthMethod) bool {
	if authMetadata == nil || authMetadata.TokenEndpointAuthMethodsSupported == nil {
		return false
	}
	for _, m := range *authMetadata.TokenEndpointAuthMethodsSupported {
		if m == method {
			return true
		}
	}
	return false
}

// asMetadataSupportsSigningAlg reports whether alg is explicitly advertised by
// the authorization server. RFC 8414 requires this metadata when JWT-based
// client authentication is supported and defines no default signing algorithm.
func asMetadataSupportsSigningAlg(authMetadata *receiverTypes.AuthorizationServerMetadata, alg jose.SignatureAlgorithm) bool {
	if authMetadata == nil || authMetadata.TokenEndpointAuthSigningAlgValuesSupported == nil ||
		len(*authMetadata.TokenEndpointAuthSigningAlgValuesSupported) == 0 {
		return false
	}
	for _, a := range *authMetadata.TokenEndpointAuthSigningAlgValuesSupported {
		if a == alg {
			return true
		}
	}
	return false
}

// resolveClientAssertionAudience returns the authorization server identifier
// used in the client_assertion aud claim. RFC 7523 requires this value to be
// agreed between the client and authorization server. Explicit configuration
// therefore takes precedence, followed by the metadata issuer. The token
// endpoint URL is a standards-compliant fallback.
func resolveClientAssertionAudience(clientAuth ClientAuthConfig, authMetadata *receiverTypes.AuthorizationServerMetadata, tokenEndpointURL string) string {
	if audience := strings.TrimSpace(clientAuth.AssertionAudience); audience != "" {
		return audience
	}
	if authMetadata != nil {
		issuerURL := url.URL(authMetadata.Issuer)
		if issuer := strings.TrimSpace(issuerURL.String()); issuer != "" {
			return issuer
		}
	}
	return tokenEndpointURL
}

// GetCredentialEntries retrieves credential entries with optional filtering.
func (w *Wallet) GetCredentialEntries(req GetCredentialEntriesRequest) ([]*SavedCredential, int, error) {
	if req.Filter != nil {
		result, err := w.credStore.GetCredentialEntries(0, nil, types.SupportedCredStoreTypes(0))
		if err != nil {
			return nil, 0, fmt.Errorf("failed to get credential entries: %w", err)
		}

		var filteredCredentials []*SavedCredential
		if result.Entries != nil {
			for _, entry := range *result.Entries {
				savedCred, err := w.convertEntryToSavedCredential(entry)
				if err != nil {
					continue // Skip invalid entries
				}

				if req.Filter(savedCred) {
					filteredCredentials = append(filteredCredentials, savedCred)
				}
			}
		}

		start := req.Offset
		if start > len(filteredCredentials) {
			start = len(filteredCredentials)
		}

		end := len(filteredCredentials)
		if req.Limit != nil && start+*req.Limit < end {
			end = start + *req.Limit
		}

		return filteredCredentials[start:end], len(filteredCredentials), nil
	}

	result, err := w.credStore.GetCredentialEntries(req.Offset, req.Limit, types.SupportedCredStoreTypes(0))
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get credential entries: %w", err)
	}

	var savedCredentials []*SavedCredential
	if result.Entries != nil {
		for _, entry := range *result.Entries {
			savedCred, err := w.convertEntryToSavedCredential(entry)
			if err != nil {
				continue // Skip invalid entries
			}
			savedCredentials = append(savedCredentials, savedCred)
		}
	}

	totalCount := 0
	if result.TotalCount != nil {
		totalCount = *result.TotalCount
	}

	return savedCredentials, totalCount, nil
}

// GetCredentialEntry retrieves a single credential entry by ID.
func (w *Wallet) GetCredentialEntry(id string) (*SavedCredential, error) {
	entry, err := w.credStore.GetCredentialEntry(id, types.SupportedCredStoreTypes(0))
	if err != nil {
		return nil, fmt.Errorf("failed to get credential entry: %w", err)
	}
	if entry == nil {
		return nil, nil
	}

	savedCred, err := w.convertEntryToSavedCredential(*entry)
	if err != nil {
		return nil, fmt.Errorf("failed to convert credential: %w", err)
	}

	return savedCred, nil
}

// FetchCredentialIssuerMetadata fetches credential issuer metadata from the given endpoint.
func (w *Wallet) FetchCredentialIssuerMetadata(endpoint *url.URL, receivingType receiverTypes.SupportedReceivingTypes) (*receiverTypes.CredentialIssuerMetadata, error) {
	uriField, err := common.ParseURIField(endpoint.String())
	if err != nil {
		return nil, fmt.Errorf("failed to parse URI field: %w", err)
	}

	return w.receiver.FetchIssuerMetadata(*uriField, receivingType)
}

// ReceiveCredential orchestrates the credential receiving flow.
func (w *Wallet) ReceiveCredential(req ReceiveCredentialRequest) (*SavedCredential, error) {
	preAuthCode, err := w.validateCredentialOffer(req.CredentialOffer)
	if err != nil {
		return nil, err
	}

	issuerMetadata, authMetadata, err := w.fetchCredentialMetadata(req)
	if err != nil {
		return nil, err
	}

	credentialConfigurationID, credentialConfiguration, serializationFlavor, err := w.selectCredentialConfiguration(req, issuerMetadata)
	if err != nil {
		return nil, err
	}

	accessToken, err := w.obtainAccessToken(req.Type, authMetadata, preAuthCode, req.TxCode)

	if err != nil {
		return nil, err
	}

	credentialJWT, err := w.requestCredential(req, issuerMetadata, accessToken, credentialConfigurationID, credentialConfiguration)
	if err != nil {
		return nil, err
	}

	return w.storeAndParseCredential(credentialJWT, serializationFlavor)
}

// validateCredentialOffer validates the credential offer and extracts pre-authorization code.
func (w *Wallet) validateCredentialOffer(offer *CredentialOffer) (string, error) {
	if offer == nil {
		return "", fmt.Errorf("credential offer is required")
	}

	if err := validateCredentialIssuerIdentifier(offer.CredentialIssuer); err != nil {
		return "", err
	}

	preAuthGrant := offer.Grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
	if preAuthGrant == nil {
		return "", fmt.Errorf("pre-authorization code is not included in the offer")
	}

	if len(offer.CredentialConfigurationIDs) == 0 {
		return "", fmt.Errorf("credential configuration IDs are empty")
	}
	seen := make(map[string]struct{}, len(offer.CredentialConfigurationIDs))
	for _, id := range offer.CredentialConfigurationIDs {
		if _, dup := seen[id]; dup {
			return "", fmt.Errorf("credential configuration IDs must be unique: %q is duplicated", id)
		}
		seen[id] = struct{}{}
	}

	preAuthCode := preAuthGrant.PreAuthorizedCode
	if preAuthCode == "" {
		return "", fmt.Errorf("pre-authorization code is not included in the offer")
	}

	return preAuthCode, nil
}

func (w *Wallet) selectCredentialConfiguration(
	req ReceiveCredentialRequest,
	issuerMetadata *receiverTypes.CredentialIssuerMetadata,
) (string, *receiverTypes.CredentialConfiguration, credential.SupportedSerializationFlavor, error) {
	if req.CredentialOffer == nil || len(req.CredentialOffer.CredentialConfigurationIDs) == 0 {
		return "", nil, "", fmt.Errorf("credential configuration IDs are empty")
	}

	defaultConfigurationID := req.CredentialOffer.CredentialConfigurationIDs[0]
	defaultFlavor := credential.JwtVc

	if req.RequestedFormat != "" {
		if req.RequestedFormat != credential.JwtVc && req.RequestedFormat != credential.SDJwtVC {
			return "", nil, "", fmt.Errorf("unsupported requested serialization format: %s", req.RequestedFormat)
		}

		if issuerMetadata == nil || issuerMetadata.CredentialConfigurationSupported == nil {
			return "", nil, "", fmt.Errorf("credential configuration metadata is required when requested format is specified")
		}

		for _, configID := range req.CredentialOffer.CredentialConfigurationIDs {
			config, ok := issuerMetadata.CredentialConfigurationSupported[configID]
			if !ok {
				continue
			}

			flavor, err := receiverOid4vci.OID4VCICredentialFormatToSerializationFlavor(config.Format)
			if err != nil {
				continue
			}
			if flavor == req.RequestedFormat {
				configCopy := config
				return configID, &configCopy, flavor, nil
			}
		}

		return "", nil, "", fmt.Errorf("no credential configuration matches requested format: %s", req.RequestedFormat)
	}

	if issuerMetadata == nil || issuerMetadata.CredentialConfigurationSupported == nil {
		return defaultConfigurationID, nil, defaultFlavor, nil
	}

	config, ok := issuerMetadata.CredentialConfigurationSupported[defaultConfigurationID]
	if !ok {
		return defaultConfigurationID, nil, defaultFlavor, nil
	}

	configCopy := config
	flavor, err := receiverOid4vci.OID4VCICredentialFormatToSerializationFlavor(config.Format)
	if err != nil {
		return "", nil, "", fmt.Errorf("unsupported credential format for configuration %q: %w", defaultConfigurationID, err)
	}

	return defaultConfigurationID, &configCopy, flavor, nil
}

func shouldAttachCredentialRequestProof(req ReceiveCredentialRequest, credentialConfiguration *receiverTypes.CredentialConfiguration) bool {
	if credentialConfiguration != nil {
		if credentialConfiguration.ProofTypesSupported != nil {
			return true
		}
		if credentialConfiguration.CryptographicBindingMethodsSupported != nil &&
			len(*credentialConfiguration.CryptographicBindingMethodsSupported) > 0 {
			return true
		}
	}

	// Keep backward-compatible behavior for existing callers that do not specify format.
	return req.RequestedFormat == ""
}

func ensureJWTProofSupported(credentialConfiguration *receiverTypes.CredentialConfiguration) error {
	if credentialConfiguration == nil || credentialConfiguration.ProofTypesSupported == nil {
		return nil
	}

	proofTypes := *credentialConfiguration.ProofTypesSupported
	if len(proofTypes) == 0 {
		return fmt.Errorf("proof_types_supported must not be empty")
	}

	for proofType := range proofTypes {
		if strings.EqualFold(strings.TrimSpace(proofType), "jwt") {
			return nil
		}
	}

	return fmt.Errorf("unsupported proof type: jwt proof is required")
}

func (w *Wallet) validateCredentialConfigurationIDs(offer *CredentialOffer, issuerMetadata *receiverTypes.CredentialIssuerMetadata) error {
	if offer == nil {
		return fmt.Errorf("credential offer is required")
	}
	if issuerMetadata == nil {
		return fmt.Errorf("issuer metadata is required")
	}
	if len(issuerMetadata.CredentialConfigurationSupported) == 0 {
		return fmt.Errorf("credential configurations supported are missing in issuer metadata")
	}

	for _, configID := range offer.CredentialConfigurationIDs {
		if _, exists := issuerMetadata.CredentialConfigurationSupported[configID]; !exists {
			return fmt.Errorf("credential configuration %q is not supported by issuer metadata", configID)
		}
	}

	return nil
}

func validateCredentialIssuerIdentifier(issuer *url.URL) error {
	if issuer == nil {
		return fmt.Errorf("credential issuer is not included in the offer")
	}

	if issuer.Scheme == "" {
		return fmt.Errorf("credential issuer must include a scheme")
	}
	if !strings.EqualFold(issuer.Scheme, "https") {
		if !env.IsHTTPAllowed() || !strings.EqualFold(issuer.Scheme, "http") {
			return fmt.Errorf("credential issuer must use https scheme")
		}
	}
	if issuer.Host == "" {
		return fmt.Errorf("credential issuer must include a host")
	}
	if issuer.RawQuery != "" || issuer.ForceQuery || issuer.Fragment != "" || issuer.RawFragment != "" {
		return fmt.Errorf("credential issuer must not include query or fragment")
	}

	return nil
}

// fetchCredentialMetadata fetches issuer and authorization server metadata.
func (w *Wallet) fetchCredentialMetadata(req ReceiveCredentialRequest) (*receiverTypes.CredentialIssuerMetadata, *receiverTypes.AuthorizationServerMetadata, error) {
	var issuerMetadata *receiverTypes.CredentialIssuerMetadata
	var err error

	if req.CachedIssuerMetadata != nil {
		issuerMetadata = req.CachedIssuerMetadata
	} else {
		issuerMetadata, err = w.FetchCredentialIssuerMetadata(req.CredentialOffer.CredentialIssuer, req.Type)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to fetch issuer metadata: %w", err)
		}
	}

	if err := w.validateCredentialConfigurationIDs(req.CredentialOffer, issuerMetadata); err != nil {
		return nil, nil, err
	}

	authorizationServers := issuerMetadata.AuthorizationServers
	if authorizationServers == nil {
		issuerAuthorizationServer, err := common.ParseURIField(req.CredentialOffer.CredentialIssuer.String())
		if err != nil {
			return nil, nil, fmt.Errorf("failed to use credential issuer as authorization server: %w", err)
		}
		authorizationServers = []common.URIField{*issuerAuthorizationServer}
	} else if len(authorizationServers) == 0 {
		return nil, nil, fmt.Errorf("authorization_servers must not be an empty array")
	}

	authMetadata, err := w.receiver.FetchAuthorizationServerMetadata(authorizationServers[0], req.Type)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch authorization server metadata: %w", err)
	}

	if authMetadata == nil {
		return nil, nil, fmt.Errorf("authorization server metadata is nil")
	}

	if authMetadata.TokenEndpoint == nil {
		return nil, nil, fmt.Errorf("token endpoint is missing on authorization server")
	}

	if _, ok := resolveClientAuthMethod(w.clientAuth, authMetadata); !ok {
		return nil, nil, errNoUsableClientAuthMethod
	}

	return issuerMetadata, authMetadata, nil
}

// obtainAccessToken obtains an access token using pre-authorization code.
func (w *Wallet) obtainAccessToken(receivingType receiverTypes.SupportedReceivingTypes, authMetadata *receiverTypes.AuthorizationServerMetadata, preAuthCode string, txCode string) (*receiverTypes.CredentialIssuanceAccessToken, error) {
	if authMetadata == nil || authMetadata.TokenEndpoint == nil {
		return nil, fmt.Errorf("token endpoint is missing on authorization server")
	}

	tokenEndpoint := *authMetadata.TokenEndpoint
	tokenEndpointURL := receiverTypes.ResolveTokenEndpointURL(tokenEndpoint)
	clientAssertionAudience := resolveClientAssertionAudience(w.clientAuth, authMetadata, tokenEndpointURL)

	authMethod, ok := resolveClientAuthMethod(w.clientAuth, authMetadata)
	if !ok {
		return nil, errNoUsableClientAuthMethod
	}

	fetchAccessToken := func(dpopNonce *string) (*receiverTypes.CredentialIssuanceAccessToken, error) {
		var tokenReqOptions []receiverTypes.TokenRequestOption
		switch authMethod {
		case receiverTypes.PrivateKeyJwt:
			assertion, err := w.generateClientAssertion(
				w.clientAuth.Key,
				w.clientAuth.ClientID,
				clientAssertionAudience,
				w.clientAuth.signatureAlgorithm(),
			)
			if err != nil {
				return nil, fmt.Errorf("failed to generate client assertion: %w", err)
			}
			tokenReqOptions = append(tokenReqOptions, receiverTypes.WithClientAssertion(w.clientAuth.ClientID, assertion))

		case receiverTypes.None:
			// client_id is OPTIONAL for the pre-authorized code grant, but an
			// authorization server that never advertised
			// pre-authorized_grant_anonymous_access_supported has told us nothing
			// about whether it serves anonymous clients. Naming the client when
			// one is configured is what lets such a server accept the request.
			if strings.TrimSpace(w.clientAuth.ClientID) != "" {
				tokenReqOptions = append(tokenReqOptions, receiverTypes.WithClientID(w.clientAuth.ClientID))
			}
		}
		if w.dpop.Enabled {
			proof, err := w.generateDPoPProof(
				w.dpop.Key,
				http.MethodPost,
				tokenEndpointURL,
				"",
				dpopNonce,
			)
			if err != nil {
				return nil, fmt.Errorf("failed to generate DPoP proof: %w", err)
			}
			tokenReqOptions = append(tokenReqOptions, receiverTypes.WithDPoPProof(proof))
		}

		return w.receiver.FetchAccessToken(receivingType, tokenEndpoint, preAuthCode, txCode, tokenReqOptions...)
	}

	accessToken, err := fetchAccessToken(nil)
	if err != nil && w.dpop.Enabled {
		if dpopNonce, ok := receiverTypes.DPoPNonceFromError(err); ok && dpopNonce != "" {
			accessToken, err = fetchAccessToken(&dpopNonce)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("failed to fetch access token: %w", err)
	}
	return accessToken, nil
}

func accessTokenNonce(accessToken *receiverTypes.CredentialIssuanceAccessToken) *string {
	if accessToken == nil || accessToken.CNonce == nil || *accessToken.CNonce == "" {
		return nil
	}
	return accessToken.CNonce
}

func accessTokenCredentialIdentifier(accessToken *receiverTypes.CredentialIssuanceAccessToken) *string {
	if accessToken == nil {
		return nil
	}

	for _, authorizationDetail := range accessToken.AuthorizationDetails {
		if authorizationDetail.Type != receiverTypes.AuthorizationDetailTypeOpenIDCredential {
			continue
		}
		for _, identifier := range authorizationDetail.CredentialIdentifiers {
			if identifier == "" {
				continue
			}
			identifierCopy := identifier
			return &identifierCopy
		}
	}

	return nil
}

// fetchCredentialNonce retrieves nonce used for proof generation from nonce endpoint,
// and falls back to c_nonce in the access token when nonce endpoint is not available.
func (w *Wallet) fetchCredentialNonce(
	receivingType receiverTypes.SupportedReceivingTypes,
	issuerMetadata *receiverTypes.CredentialIssuerMetadata,
	accessToken *receiverTypes.CredentialIssuanceAccessToken,
) (*string, error) {
	fallbackNonce := accessTokenNonce(accessToken)

	if issuerMetadata.NonceEndpoint == nil {
		return fallbackNonce, nil
	}

	nonce, err := w.receiver.FetchNonce(receivingType, *issuerMetadata.NonceEndpoint)
	if err != nil {
		if fallbackNonce != nil {
			return fallbackNonce, nil
		}
		return nil, fmt.Errorf("failed to fetch nonce: %w", err)
	}

	if nonce != nil && *nonce != "" {
		return nonce, nil
	}

	if fallbackNonce != nil {
		return fallbackNonce, nil
	}

	return nil, fmt.Errorf("nonce response does not contain c_nonce or nonce")
}

func (w *Wallet) fetchDPoPNonce(issuerMetadata *receiverTypes.CredentialIssuerMetadata) (*string, error) {
	if issuerMetadata == nil || issuerMetadata.NonceEndpoint == nil {
		return nil, fmt.Errorf("issuer metadata does not contain nonce endpoint")
	}

	nonceEndpointURL := url.URL(*issuerMetadata.NonceEndpoint)
	if !env.IsHTTPAllowed() && !strings.EqualFold(nonceEndpointURL.Scheme, "https") {
		return nil, fmt.Errorf("unsupported URL scheme for OID4VCI endpoint: %q (https required)", nonceEndpointURL.Scheme)
	}

	req, err := http.NewRequest(http.MethodPost, nonceEndpointURL.String(), http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create DPoP nonce request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := dpopNonceHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch DPoP nonce: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxDPoPNonceResponseBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read DPoP nonce response: %w", err)
	}
	if int64(len(bodyBytes)) > maxDPoPNonceResponseBodyBytes {
		return nil, fmt.Errorf("DPoP nonce endpoint response exceeds %d bytes", maxDPoPNonceResponseBodyBytes)
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("DPoP nonce endpoint returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	nonce := strings.TrimSpace(resp.Header.Get("DPoP-Nonce"))
	if nonce == "" {
		return nil, fmt.Errorf("DPoP nonce endpoint response does not contain DPoP-Nonce header")
	}

	return &nonce, nil
}

// requestCredential requests the credential from the issuer with JWT proof.
func (w *Wallet) requestCredential(
	req ReceiveCredentialRequest,
	issuerMetadata *receiverTypes.CredentialIssuerMetadata,
	accessToken *receiverTypes.CredentialIssuanceAccessToken,
	credentialConfigurationID string,
	credentialConfiguration *receiverTypes.CredentialConfiguration,
) (*string, error) {
	credentialIdentifier := accessTokenCredentialIdentifier(accessToken)
	if credentialIdentifier != nil {
		credentialConfigurationID = ""
	}

	var proof *string
	attachProof := shouldAttachCredentialRequestProof(req, credentialConfiguration)
	if attachProof {
		if req.Key == nil {
			return nil, fmt.Errorf("key entry is required")
		}

		if err := ensureJWTProofSupported(credentialConfiguration); err != nil {
			return nil, err
		}

		proofBindingMethod := resolveCredentialRequestProofBindingMethod(credentialConfiguration)

		var did *idprofTypes.IdentityProfile
		if proofBindingMethod == credentialRequestProofBindingMethodKID {
			didGenerated, err := w.GenerateDID(DIDCreateOptions{
				TypeID:    "did:key",
				PublicKey: req.Key.PublicKey(),
			})
			if err != nil {
				return nil, fmt.Errorf("failed to generate DID: %w", err)
			}
			did = didGenerated
		}

		nonce, err := w.fetchCredentialNonce(req.Type, issuerMetadata, accessToken)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch nonce for credential proof: %w", err)
		}

		proofValue, err := w.generateJWTProof(
			req.Key,
			did,
			nonce,
			issuerMetadata.CredentialIssuer,
			nil,
			proofBindingMethod,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to generate JWT proof: %w", err)
		}

		proof = &proofValue
	}

	var credentialDefinition *receiverTypes.CredentialDefinition
	if credentialConfiguration != nil {
		credentialDefinition = credentialConfiguration.CredentialDefinition
	}

	receiveCredential := func(dpopNonce *string) (*string, error) {
		var options *receiverTypes.CredentialRequestOptions
		if strings.EqualFold(accessToken.TokenType, "DPoP") {
			if w.dpop.Key == nil {
				return nil, fmt.Errorf("dpop key is required for DPoP access token")
			}
			dpopProof, err := w.generateDPoPProof(w.dpop.Key, http.MethodPost, issuerMetadata.CredentialEndpoint.String(), accessToken.Token, dpopNonce)
			if err != nil {
				return nil, fmt.Errorf("failed to generate DPoP proof: %w", err)
			}
			options = &receiverTypes.CredentialRequestOptions{
				DPoPProofJWT: &dpopProof,
			}
		}

		return w.receiver.ReceiveCredential(
			req.Type,
			issuerMetadata.CredentialEndpoint,
			credentialConfigurationID,
			credentialIdentifier,
			*accessToken,
			credentialDefinition,
			proof,
			options,
		)
	}

	credentialJWT, err := receiveCredential(nil)
	if err != nil && strings.EqualFold(accessToken.TokenType, "DPoP") && errors.Is(err, receiverTypes.ErrUseDPoPNonce) {
		dpopNonce, nonceErr := w.fetchDPoPNonce(issuerMetadata)
		if nonceErr != nil {
			return nil, fmt.Errorf("failed to fetch DPoP nonce: %w", nonceErr)
		}
		credentialJWT, err = receiveCredential(dpopNonce)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to receive credential: %w", err)
	}

	return credentialJWT, nil
}

// storeAndParseCredential stores the credential and parses it for return.
func (w *Wallet) storeAndParseCredential(credentialJWT *string, serializationFlavor credential.SupportedSerializationFlavor) (*SavedCredential, error) {
	if serializationFlavor == "" {
		serializationFlavor = credential.JwtVc
	}

	credentialEntry := types.CredentialEntry{
		Id:         uuid.New().String(),
		ReceivedAt: time.Now(),
		Raw:        []byte(*credentialJWT),
		MimeType:   string(serializationFlavor),
	}

	if err := w.credStore.SaveCredentialEntry(credentialEntry, types.SupportedCredStoreTypes(0)); err != nil {
		return nil, fmt.Errorf("failed to save credential entry: %w", err)
	}

	f, err := credentialEntry.SerializationFlavor()
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential: %w", err)
	}

	credential, err := w.serializer.DeserializeCredential(f, credentialEntry.Raw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential: %w", err)
	}

	return &SavedCredential{
		Credential: credential,
		Entry:      &credentialEntry,
	}, nil
}

// PresentCredential orchestrates the credential presentation flow.
func (w *Wallet) PresentCredential(uriString string, key IKeyEntry, options serializerTypes.SerializePresentationOptions) (string, error) {
	return w.PresentCredentialWithOptions(uriString, key, &PresentCredentialOptions{SerializeOptions: options})
}

// PresentCredentialWithOptions orchestrates presentation and invokes redirect handler if provided.
func (w *Wallet) PresentCredentialWithOptions(uriString string, key IKeyEntry, options *PresentCredentialOptions) (string, error) {
	var serializeOptions serializerTypes.SerializePresentationOptions
	var onRedirect RedirectHandler
	if options != nil {
		serializeOptions = options.SerializeOptions
		onRedirect = options.OnRedirect
	}

	req, endpoint, err := w.parseAuthorizationRequest(uriString)
	if err != nil {
		return "", err
	}

	credentials, flavor, err := w.selectCredentialsForPresentation(req)
	if err != nil {
		return "", err
	}

	if serializeOptions == nil {
		serializeOptions, err = w.serializer.GetDefaultOption(*flavor)
		if err != nil {
			return "", err
		}
	}
	applyOID4VPRequestOptions(req, serializeOptions)

	descriptorMap, err := w.buildDescriptorMap(credentials, flavor)
	if err != nil {
		return "", err
	}

	presentation, err := w.buildPresentation(credentials, flavor, descriptorMap, key, req)
	if err != nil {
		return "", err
	}

	redirectURI, err := w.submitPresentation(presentation, flavor, endpoint, descriptorMap, req, key, serializeOptions)
	if err != nil {
		return "", err
	}
	if redirectURI != "" && onRedirect != nil {
		if err := onRedirect(redirectURI); err != nil {
			return redirectURI, err
		}
	}

	return redirectURI, nil
}

// parseAuthorizationRequest parses the authorization request URI and determines the endpoint.
func (w *Wallet) parseAuthorizationRequest(uriString string) (*oid4vp.CredentialPresentationRequest, *url.URL, error) {
	req, err := w.presenter.ParseRequestURI(uriString)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse request URI: %w", err)
	}

	if req.RedirectURI == "" {
		return nil, nil, fmt.Errorf("redirect_uri is not specified")
	}

	var endpoint *url.URL
	if req.ResponseMode == oid4vp.OAuthAuthzReqResponseModeDirectPost {
		if req.ResponseURI == "" {
			return nil, nil, fmt.Errorf("response_uri is not specified for response_mode=direct_post")
		}
		endpoint, err = url.Parse(req.ResponseURI)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid response_uri: %w", err)
		}
	} else {
		endpoint, err = url.Parse(req.RedirectURI)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid redirect_uri: %w", err)
		}
	}

	if req.PresentationDefinition == nil {
		return nil, nil, fmt.Errorf("presentation definition is not specified")
	}

	return req, endpoint, nil
}

// selectCredentialsForPresentation selects credentials matching the presentation definition.
func (w *Wallet) selectCredentialsForPresentation(req *oid4vp.CredentialPresentationRequest) ([]*SavedCredential, *credential.SupportedSerializationFlavor, error) {
	entries, _, err := w.GetCredentialEntries(GetCredentialEntriesRequest{
		Offset: 0,
		Limit:  nil,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get credential entries: %w", err)
	}
	if len(entries) == 0 {
		return nil, nil, fmt.Errorf("no credentials available for presentation")
	}

	selectedCredentials := newestCredentials(entries, 1)

	// Validate that all selected credentials have the same serialization flavor
	serializationFlavor, err := w.validateSerializationFlavor(selectedCredentials)
	if err != nil {
		return nil, nil, err
	}

	return selectedCredentials, serializationFlavor, nil
}

func newestCredentials(entries []*SavedCredential, limit int) []*SavedCredential {
	if len(entries) == 0 || limit <= 0 {
		return nil
	}

	sorted := append([]*SavedCredential(nil), entries...)
	sort.SliceStable(sorted, func(i, j int) bool {
		left := sorted[i]
		right := sorted[j]

		if left == nil || left.Entry == nil {
			return false
		}
		if right == nil || right.Entry == nil {
			return true
		}

		return left.Entry.ReceivedAt.After(right.Entry.ReceivedAt)
	})

	if limit > len(sorted) {
		limit = len(sorted)
	}

	return sorted[:limit]
}

// validateSerializationFlavor ensures all credentials have the same serialization flavor.
func (w *Wallet) validateSerializationFlavor(credentials []*SavedCredential) (*credential.SupportedSerializationFlavor, error) {
	var serializationFlavor *credential.SupportedSerializationFlavor

	for _, cred := range credentials {
		sf, err := cred.Entry.SerializationFlavor()
		if err != nil {
			return nil, fmt.Errorf("credential entry has no serialization flavor information")
		}

		if serializationFlavor == nil {
			serializationFlavor = &sf
		} else if *serializationFlavor != sf {
			return nil, fmt.Errorf("credentials have different serialization flavors")
		}
	}

	if serializationFlavor == nil {
		return nil, fmt.Errorf("failed to detect serialization flavor")
	}

	return serializationFlavor, nil
}

// buildDescriptorMap builds the presentation submission descriptor map.
func (w *Wallet) buildDescriptorMap(credentials []*SavedCredential, flavor *credential.SupportedSerializationFlavor) ([]presenterTypes.DescriptorMapItem, error) {
	vcFormat, vpFormat, err := flavor.OID4VPFormatIdentifier()
	if err != nil {
		return nil, fmt.Errorf("unsupported serialization format: %w", err)
	}

	var descriptorMap []presenterTypes.DescriptorMapItem
	for i := range credentials {
		descriptionItemID := uuid.New().String()
		descriptorPath := "$"
		if len(credentials) > 1 {
			descriptorPath = fmt.Sprintf("$[%d]", i)
		}
		// Temporary compatibility workaround:
		// the current verifier/request-object flow still requires
		// presentation_submission.descriptor_map, and dc+sd-jwt must point to the
		// combined vp_token itself with path "$" instead of JWT-VP style nested paths.
		// This format-specific branching does not belong in wallet core long term and
		// should be removed or moved once the verifier/request-object flow is
		// reorganized around DCQL.
		if vpFormat == "dc+sd-jwt" {
			descriptorMap = append(descriptorMap, presenterTypes.DescriptorMapItem{
				ID:     descriptionItemID,
				Format: vpFormat,
				Path:   descriptorPath,
			})
			continue
		}

		descriptorMap = append(descriptorMap, presenterTypes.DescriptorMapItem{
			ID:     descriptionItemID,
			Format: vpFormat,
			Path:   descriptorPath,
			PathNested: &presenterTypes.DescriptorMapItem{
				ID:     descriptionItemID,
				Format: vcFormat,
				Path:   fmt.Sprintf("$.verifiableCredential[%d]", i),
			},
		})
	}

	return descriptorMap, nil
}

// buildPresentation builds the credential presentation.
func (w *Wallet) buildPresentation(credentials []*SavedCredential, flavor *credential.SupportedSerializationFlavor, descriptorMap []presenterTypes.DescriptorMapItem, key IKeyEntry, req *oid4vp.CredentialPresentationRequest) (*credential.CredentialPresentation, error) {
	did, err := w.GenerateDID(DIDCreateOptions{
		TypeID:    "did:key",
		PublicKey: key.PublicKey(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to generate DID: %w", err)
	}

	var serializedCredentials [][]byte
	for _, entry := range credentials {
		serializedCredentials = append(serializedCredentials, entry.Entry.Raw)
	}

	presentation := &credential.CredentialPresentation{
		ID:          "urn:uuid:" + uuid.New().String(),
		Types:       []string{"VerifiablePresentation"},
		Credentials: serializedCredentials,
		Holder:      did.ID,
		Nonce:       &req.Nonce,
	}

	return presentation, nil
}

func applyOID4VPRequestOptions(req *oid4vp.CredentialPresentationRequest, options serializerTypes.SerializePresentationOptions) {
	if options == nil || req == nil || req.OAuthAuthzRequest == nil {
		return
	}
	options.SetAudience(req.ClientID)
	options.SetNonce(req.Nonce)
}

// submitPresentation serializes and submits the presentation to the verifier.
func (w *Wallet) submitPresentation(presentation *credential.CredentialPresentation, flavor *credential.SupportedSerializationFlavor, endpoint *url.URL, descriptorMap []presenterTypes.DescriptorMapItem, req *oid4vp.CredentialPresentationRequest, key IKeyEntry, options serializerTypes.SerializePresentationOptions) (string, error) {
	if len(req.TransactionData) > 0 {
		if sdOpts, ok := options.(*sdjwtvc.SdJwtVcPresentationOptions); ok && sdOpts != nil {
			transactionDataHashesAlg := req.TransactionDataHashesAlg
			if transactionDataHashesAlg == "" {
				// OID4VP transaction_data_hashes_alg default when omitted.
				transactionDataHashesAlg = "sha-256"
			}

			sdOpts.TransactionData = req.TransactionData
			sdOpts.TransactionDataHashesAlg = transactionDataHashesAlg
		}
	}

	bytes, _, err := w.serializer.SerializePresentation(
		*flavor,
		presentation,
		key,
		options,
	)
	if err != nil {
		return "", fmt.Errorf("failed to serialize presentation: %w", err)
	}

	presentationSubmission := presenterTypes.PresentationSubmission{
		ID:            uuid.New().String(),
		DefinitionID:  req.PresentationDefinition.ID,
		DescriptorMap: descriptorMap,
	}

	presentationRequest := &presenterTypes.PresentationRequest{
		State:          req.State,
		ClientMetadata: req.ClientMetadata,
	}

	if req.ClientMetadata != nil {
		presentationRequest.AuthorizationEncryptedRespAlg = req.ClientMetadata.AuthorizationEncryptedResponseAlg
		presentationRequest.AuthorizationEncryptedRespEnc = req.ClientMetadata.AuthorizationEncryptedResponseEnc
	}

	redirectURI, err := w.presenter.Present(presenterTypes.Oid4vp, *endpoint, bytes, presentationSubmission, presentationRequest)
	if err != nil {
		return "", err
	}
	return redirectURI, nil
}
