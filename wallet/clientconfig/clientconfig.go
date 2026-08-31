// Package clientconfig loads OAuth client authentication settings for the
// wallet from a JSON configuration file.
//
// The file holds one entry per registered client, using the metadata names
// registered in the IANA OAuth Dynamic Client Registration Metadata registry
// (RFC 7591 and OpenID Connect Dynamic Client Registration 1.0):
//
//	{
//	  "clients": [
//	    {
//	      "client_id": "wallet-id",
//	      "token_endpoint_auth_method": "private_key_jwt",
//	      "token_endpoint_auth_signing_alg": "ES256",
//	      "jwks": { "keys": [ { "kty": "EC", "crv": "P-256", "kid": "...", "x": "...", "y": "..." } ] }
//	    }
//	  ]
//	}
//
// The jwks member carries public keys only: OpenID Connect Dynamic Client
// Registration 1.0 section 2 states that the JWK Set MUST NOT contain private
// or symmetric key values, so the same file can be handed to an authorization
// server as a registration request. The matching private key is supplied
// separately with WithPrivateJWKFile, or out of band with WithKeyEntry when it
// lives in an HSM, a secure enclave or a KMS.
//
// Loading never happens implicitly. Callers pass the result to
// wallet.NewWalletWithConfig, which keeps configuring the wallet in Go the
// supported alternative:
//
//	clientAuth, err := clientconfig.Load(
//		"wallet-clients.json",
//		clientconfig.WithClientID("wallet-id"),
//		clientconfig.WithPrivateJWKFile("client-private.jwks.json"),
//	)
//	if err != nil {
//		return err
//	}
//	w, err := wallet.NewWalletWithConfig(wallet.Config{ClientAuth: clientAuth})
package clientconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"runtime"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet"
	joseutil "github.com/trustknots/vcknots/wallet/common/jose"
	"github.com/trustknots/vcknots/wallet/keystore"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// Sentinel errors for client configuration loading.
var (
	ErrInvalidDocument         = errors.New("invalid client configuration document")
	ErrNoClientEntries         = errors.New("no client entries in client configuration")
	ErrClientNotFound          = errors.New("client_id not found in client configuration")
	ErrAmbiguousClient         = errors.New("multiple client entries: client_id must be specified")
	ErrDuplicateClientID       = errors.New("duplicate client_id in client configuration")
	ErrUnsupportedAuthMethod   = errors.New("unsupported token_endpoint_auth_method")
	ErrUnsupportedSigningAlg   = errors.New("unsupported token_endpoint_auth_signing_alg")
	ErrSigningAlgMismatch      = errors.New("JWK alg does not match token_endpoint_auth_signing_alg")
	ErrSigningKeyNotFound      = errors.New("no usable signing key for the selected client")
	ErrAmbiguousSigningKey     = errors.New("multiple candidate signing keys: kid must be specified")
	ErrJWKSConflict            = errors.New("jwks and jwks_uri must not both be present")
	ErrJWKSURIUnsupported      = errors.New("jwks_uri alone cannot supply a local signing key")
	ErrPrivateKeyInJWKS        = errors.New("jwks must not contain private key values")
	ErrKeyMismatch             = errors.New("supplied signing key does not match the registered public key")
	ErrUnusedSigningKey        = errors.New("a signing key was supplied for a client that signs nothing")
	ErrInsecureFilePermissions = errors.New("private key file is readable by group or others")
)

// Document is the on-disk representation of the configuration file.
//
// Clients is the canonical member name, matching server/samples/oauth-clients.json.
// Client is accepted as an alias so that a file written with the singular key
// still loads; entries from both are used, in file order.
type Document struct {
	Clients []Client `json:"clients,omitempty"`
	Client  []Client `json:"client,omitempty"`
}

// Client mirrors the OAuth client metadata names relevant to wallet-side
// client authentication.
//
// ClientAssertionAudience is a local extension, sharing its name with the
// server-side sample configuration. It overrides the aud claim of the
// client_assertion. Leaving it empty is the recommended default: the wallet
// then resolves aud from the authorization server metadata issuer, which
// draft-ietf-oauth-security-topics-update requires clients to use.
type Client struct {
	ClientID                    string              `json:"client_id"`
	TokenEndpointAuthMethod     string              `json:"token_endpoint_auth_method"`
	TokenEndpointAuthSigningAlg string              `json:"token_endpoint_auth_signing_alg,omitempty"`
	ClientAssertionAudience     string              `json:"client_assertion_audience,omitempty"`
	JWKS                        *jose.JSONWebKeySet `json:"jwks,omitempty"`
	JWKSURI                     string              `json:"jwks_uri,omitempty"`
}

// Entries returns the clients and client members merged, preserving file order.
func (d *Document) Entries() []Client {
	if d == nil {
		return nil
	}
	entries := make([]Client, 0, len(d.Clients)+len(d.Client))
	entries = append(entries, d.Clients...)
	entries = append(entries, d.Client...)
	return entries
}

type options struct {
	clientID                string
	keyID                   string
	keyEntry                wallet.IKeyEntry
	privateJWKPath          string
	assertionAudience       string
	assertionAudienceSet    bool
	allowInsecurePermission bool
}

// Option customizes how a client configuration is loaded.
type Option func(*options)

// WithClientID selects one entry out of the configured clients by client_id.
// It is required when the file holds more than one entry.
func WithClientID(clientID string) Option {
	return func(o *options) { o.clientID = clientID }
}

// WithKeyID selects one JWK out of the client's jwks by kid. It is required
// when the client registers more than one signing key.
func WithKeyID(kid string) Option {
	return func(o *options) { o.keyID = kid }
}

// WithKeyEntry supplies the signing key out of band, for keys held in an HSM,
// a secure enclave or a KMS that cannot be exported into a file. It takes
// precedence over WithPrivateJWKFile, and its public key is checked against
// the registered jwks entry by RFC 7638 thumbprint.
func WithKeyEntry(key wallet.IKeyEntry) Option {
	return func(o *options) { o.keyEntry = key }
}

// WithPrivateJWKFile reads the signing key from a separate file holding either
// a single JWK or a JWK Set, so that the client configuration itself stays
// free of private key material and can be committed.
//
// The file must not be readable by group or others; see
// AllowInsecureFilePermissions to opt out of that check.
func WithPrivateJWKFile(path string) Option {
	return func(o *options) { o.privateJWKPath = path }
}

// WithAssertionAudience overrides the client_assertion_audience of the
// selected entry. Passing an empty string clears it, restoring the default of
// resolving aud from the authorization server metadata issuer.
func WithAssertionAudience(audience string) Option {
	return func(o *options) {
		o.assertionAudience = audience
		o.assertionAudienceSet = true
	}
}

// AllowInsecureFilePermissions disables the file permission check applied to
// files carrying private key material. It exists for Windows, where Unix file
// modes are not meaningful, and for CI sandboxes that cannot control them.
func AllowInsecureFilePermissions() Option {
	return func(o *options) { o.allowInsecurePermission = true }
}

// Load reads path and returns the client authentication configuration for the
// selected client, ready to be placed in wallet.Config.ClientAuth.
func Load(path string, opts ...Option) (wallet.ClientAuthConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return wallet.ClientAuthConfig{}, fmt.Errorf("failed to read client configuration %q: %w", path, err)
	}

	document, err := parseDocument(data)
	if err != nil {
		return wallet.ClientAuthConfig{}, err
	}

	return build(document, newOptions(opts))
}

// Parse builds the client authentication configuration from an in-memory
// document, for embedded configurations and tests. It applies the same
// validation as Load; WithPrivateJWKFile still reads that file from disk and
// still requires it to be mode 0600.
func Parse(data []byte, opts ...Option) (wallet.ClientAuthConfig, error) {
	document, err := parseDocument(data)
	if err != nil {
		return wallet.ClientAuthConfig{}, err
	}
	return build(document, newOptions(opts))
}

// LoadDocument reads and parses path without resolving a client, for callers
// that want to inspect or list the configured entries.
func LoadDocument(path string) (*Document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read client configuration %q: %w", path, err)
	}
	return parseDocument(data)
}

func newOptions(opts []Option) *options {
	resolved := &options{}
	for _, opt := range opts {
		if opt != nil {
			opt(resolved)
		}
	}
	if runtime.GOOS == "windows" {
		resolved.allowInsecurePermission = true
	}
	return resolved
}

func parseDocument(data []byte) (*Document, error) {
	var document Document
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("failed to parse client configuration: %w: %w", err, ErrInvalidDocument)
	}
	return &document, nil
}

func build(document *Document, opts *options) (wallet.ClientAuthConfig, error) {
	entry, err := selectClient(document, opts.clientID)
	if err != nil {
		return wallet.ClientAuthConfig{}, err
	}

	method, err := parseAuthMethod(entry.TokenEndpointAuthMethod)
	if err != nil {
		return wallet.ClientAuthConfig{}, err
	}

	audience := entry.ClientAssertionAudience
	if opts.assertionAudienceSet {
		audience = opts.assertionAudience
	}

	// The registered key set is checked for every method, so that a private
	// key never slips into a file meant to be published.
	if err := validateJWKS(entry); err != nil {
		return wallet.ClientAuthConfig{}, err
	}

	if method == receiverTypes.None {
		if opts.keyEntry != nil || strings.TrimSpace(opts.privateJWKPath) != "" {
			return wallet.ClientAuthConfig{}, fmt.Errorf(
				"client %q uses token_endpoint_auth_method %q, which signs nothing: %w",
				entry.ClientID, method, ErrUnusedSigningKey)
		}
		return wallet.ClientAuthConfig{Method: receiverTypes.None}, nil
	}

	if strings.TrimSpace(entry.ClientID) == "" {
		return wallet.ClientAuthConfig{}, fmt.Errorf(
			"client_id is required for %s: %w", method, ErrInvalidDocument)
	}

	alg, err := parseSigningAlg(entry.TokenEndpointAuthSigningAlg)
	if err != nil {
		return wallet.ClientAuthConfig{}, err
	}

	key, err := resolveSigningKey(entry, alg, opts)
	if err != nil {
		return wallet.ClientAuthConfig{}, err
	}

	return wallet.ClientAuthConfig{
		Method:            method,
		ClientID:          entry.ClientID,
		Key:               key,
		AssertionAudience: audience,
		SigningAlg:        alg,
	}, nil
}

func selectClient(document *Document, clientID string) (Client, error) {
	entries := document.Entries()
	if len(entries) == 0 {
		return Client{}, ErrNoClientEntries
	}

	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		id := entry.ClientID
		if _, duplicated := seen[id]; duplicated {
			return Client{}, fmt.Errorf("client_id %q appears more than once: %w", id, ErrDuplicateClientID)
		}
		seen[id] = struct{}{}
	}

	if clientID == "" {
		if len(entries) > 1 {
			return Client{}, fmt.Errorf(
				"client configuration holds %d entries: %w", len(entries), ErrAmbiguousClient)
		}
		return entries[0], nil
	}

	for _, entry := range entries {
		if entry.ClientID == clientID {
			return entry, nil
		}
	}
	return Client{}, fmt.Errorf("client_id %q: %w", clientID, ErrClientNotFound)
}

// parseAuthMethod maps the configured token_endpoint_auth_method onto the
// methods the wallet implements. The remaining registered values are rejected
// here rather than at wallet construction, so that a configuration mistake
// surfaces while reading the file.
func parseAuthMethod(method string) (receiverTypes.TokenEndpointAuthMethod, error) {
	switch receiverTypes.TokenEndpointAuthMethod(strings.TrimSpace(method)) {
	case "", receiverTypes.None:
		return receiverTypes.None, nil
	case receiverTypes.PrivateKeyJwt:
		return receiverTypes.PrivateKeyJwt, nil
	default:
		return "", fmt.Errorf(
			"%q is not implemented by the wallet (supported: none, private_key_jwt): %w",
			method, ErrUnsupportedAuthMethod)
	}
}

// parseSigningAlg resolves token_endpoint_auth_signing_alg. OpenID Connect
// Dynamic Client Registration 1.0 leaves the value optional; the wallet
// defaults to ES256, and supports only the ECDSA algorithms its signing keys
// can carry.
func parseSigningAlg(alg string) (jose.SignatureAlgorithm, error) {
	trimmed := strings.TrimSpace(alg)
	if trimmed == "" {
		return jose.ES256, nil
	}

	parsed, err := joseutil.ParseAlgorithm(trimmed)
	if err != nil {
		return "", fmt.Errorf("%q: %w", alg, ErrUnsupportedSigningAlg)
	}

	switch parsed {
	case jose.ES256, jose.ES384, jose.ES512:
		return parsed, nil
	default:
		return "", fmt.Errorf(
			"%q is not usable for client authentication (supported: ES256, ES384, ES512): %w",
			alg, ErrUnsupportedSigningAlg)
	}
}

// validateJWKS checks the shape of the registered key set.
//
// jwks is the public key set the authorization server is given. Keeping it
// free of private values is what lets the same file serve as a client
// registration request, and is required by OpenID Connect Dynamic Client
// Registration 1.0 section 2.
//
// A jwks written as a bare JWK rather than a JWK Set unmarshals into an empty
// set, which would silently skip both that check and the comparison against
// the supplied signing key, so it is rejected here.
func validateJWKS(entry Client) error {
	if entry.JWKS == nil {
		return nil
	}
	if strings.TrimSpace(entry.JWKSURI) != "" {
		return ErrJWKSConflict
	}
	if len(entry.JWKS.Keys) == 0 {
		return fmt.Errorf(
			"client %q has a jwks with no keys member; jwks must be a JWK Set: %w",
			entry.ClientID, ErrInvalidDocument)
	}
	for _, key := range entry.JWKS.Keys {
		if !key.IsPublic() {
			return fmt.Errorf(
				"key %q in jwks carries private key material; keep it in a separate file and pass WithPrivateJWKFile: %w",
				key.KeyID, ErrPrivateKeyInJWKS)
		}
	}
	return nil
}

func resolveSigningKey(entry Client, alg jose.SignatureAlgorithm, opts *options) (wallet.IKeyEntry, error) {
	registered, err := selectRegisteredJWK(entry, alg, opts.keyID)
	if err != nil {
		return nil, err
	}

	key, err := loadExternalKey(opts)
	if err != nil {
		return nil, err
	}

	if key == nil {
		if registered == nil {
			if strings.TrimSpace(entry.JWKSURI) != "" {
				return nil, fmt.Errorf(
					"client %q publishes its keys through jwks_uri: %w", entry.ClientID, ErrJWKSURIUnsupported)
			}
			return nil, fmt.Errorf("client %q: %w", entry.ClientID, ErrSigningKeyNotFound)
		}
		return nil, fmt.Errorf(
			"client %q registers public keys only; supply the private key with WithPrivateJWKFile or WithKeyEntry: %w",
			entry.ClientID, ErrSigningKeyNotFound)
	}

	if registered != nil {
		if err := requireSamePublicKey(*registered, key.PublicKey()); err != nil {
			return nil, fmt.Errorf("client %q: %w", entry.ClientID, err)
		}
	}
	return key, nil
}

// selectRegisteredJWK picks the JWK the client is registered with. Keys marked
// for encryption are skipped, and an alg on the key itself must agree with
// token_endpoint_auth_signing_alg.
func selectRegisteredJWK(entry Client, alg jose.SignatureAlgorithm, keyID string) (*jose.JSONWebKey, error) {
	if entry.JWKS == nil || len(entry.JWKS.Keys) == 0 {
		return nil, nil
	}

	candidates := make([]jose.JSONWebKey, 0, len(entry.JWKS.Keys))
	for _, key := range entry.JWKS.Keys {
		if keyID != "" && key.KeyID != keyID {
			continue
		}
		if use := strings.TrimSpace(key.Use); use != "" && use != "sig" {
			if keyID != "" {
				return nil, fmt.Errorf(
					"key %q has use %q and cannot sign: %w", key.KeyID, key.Use, ErrSigningKeyNotFound)
			}
			continue
		}
		candidates = append(candidates, key)
	}

	if len(candidates) == 0 {
		if keyID != "" {
			return nil, fmt.Errorf("kid %q: %w", keyID, ErrSigningKeyNotFound)
		}
		return nil, fmt.Errorf("jwks holds no signing key: %w", ErrSigningKeyNotFound)
	}

	// A key may pin its own alg. When several keys remain, the ones that
	// disagree with token_endpoint_auth_signing_alg are simply meant for a
	// different algorithm; when only one remains, the disagreement is a
	// configuration mistake worth reporting.
	if len(candidates) > 1 {
		matching := make([]jose.JSONWebKey, 0, len(candidates))
		for _, key := range candidates {
			if keyAlg := strings.TrimSpace(key.Algorithm); keyAlg == "" || keyAlg == string(alg) {
				matching = append(matching, key)
			}
		}
		if len(matching) > 0 {
			candidates = matching
		}
	}

	if len(candidates) > 1 {
		return nil, fmt.Errorf("jwks holds %d signing keys: %w", len(candidates), ErrAmbiguousSigningKey)
	}

	selected := candidates[0]
	if keyAlg := strings.TrimSpace(selected.Algorithm); keyAlg != "" && keyAlg != string(alg) {
		return nil, fmt.Errorf(
			"key %q declares alg %q but token_endpoint_auth_signing_alg is %q: %w",
			selected.KeyID, keyAlg, alg, ErrSigningAlgMismatch)
	}
	return &selected, nil
}

func loadExternalKey(opts *options) (wallet.IKeyEntry, error) {
	if opts.keyEntry != nil {
		return opts.keyEntry, nil
	}
	if strings.TrimSpace(opts.privateJWKPath) == "" {
		return nil, nil
	}

	if !opts.allowInsecurePermission {
		if err := requireSecurePermissions(opts.privateJWKPath); err != nil {
			return nil, err
		}
	}

	data, err := os.ReadFile(opts.privateJWKPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private JWK %q: %w", opts.privateJWKPath, err)
	}

	jwk, err := selectPrivateJWK(data, opts.keyID)
	if err != nil {
		return nil, fmt.Errorf("private JWK %q: %w", opts.privateJWKPath, err)
	}

	key, err := keystore.NewKeyEntryFromJWK(jwk)
	if err != nil {
		return nil, fmt.Errorf("private JWK %q: %w", opts.privateJWKPath, err)
	}
	return key, nil
}

// selectPrivateJWK accepts either a JWK Set or a bare JWK, so that a key
// exported by either convention loads without conversion.
func selectPrivateJWK(data []byte, keyID string) (jose.JSONWebKey, error) {
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(data, &set); err == nil && len(set.Keys) > 0 {
		if keyID != "" {
			matches := set.Key(keyID)
			if len(matches) == 0 {
				return jose.JSONWebKey{}, fmt.Errorf("kid %q: %w", keyID, ErrSigningKeyNotFound)
			}
			if len(matches) > 1 {
				return jose.JSONWebKey{}, fmt.Errorf("kid %q matches %d keys: %w", keyID, len(matches), ErrAmbiguousSigningKey)
			}
			return matches[0], nil
		}
		if len(set.Keys) > 1 {
			return jose.JSONWebKey{}, fmt.Errorf("JWK Set holds %d keys: %w", len(set.Keys), ErrAmbiguousSigningKey)
		}
		return set.Keys[0], nil
	}

	var jwk jose.JSONWebKey
	if err := json.Unmarshal(data, &jwk); err != nil {
		return jose.JSONWebKey{}, fmt.Errorf("failed to parse JWK: %w: %w", err, ErrInvalidDocument)
	}
	if keyID != "" && jwk.KeyID != keyID {
		return jose.JSONWebKey{}, fmt.Errorf("kid %q: %w", keyID, ErrSigningKeyNotFound)
	}
	return jwk, nil
}

func requireSamePublicKey(registered, supplied jose.JSONWebKey) error {
	equal, err := joseutil.EqualPublicKey(registered.Public(), supplied)
	if err != nil {
		return fmt.Errorf("failed to compare signing keys: %w", err)
	}
	if !equal {
		return ErrKeyMismatch
	}
	return nil
}

// requireSecurePermissions rejects files that group or others can read, the
// usual way a committed or shared signing key leaks.
func requireSecurePermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to stat %q: %w", path, err)
	}
	if mode := info.Mode().Perm(); mode&fs.FileMode(0o077) != 0 {
		return fmt.Errorf("%q has mode %#o, want 0600: %w", path, mode, ErrInsecureFilePermissions)
	}
	return nil
}
