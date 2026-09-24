// Package verifier provides credential verification functionality with algorithm dispatching
package verifier

import (
	"fmt"
	"sync"

	"github.com/go-jose/go-jose/v4"
	commonJOSE "github.com/trustknots/vcknots/wallet/common/jose"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/verifier/plugins/eddsa"
	"github.com/trustknots/vcknots/wallet/verifier/plugins/es256"
	"github.com/trustknots/vcknots/wallet/verifier/plugins/es384"
	"github.com/trustknots/vcknots/wallet/verifier/plugins/es512"
	"github.com/trustknots/vcknots/wallet/verifier/plugins/ps256"
	"github.com/trustknots/vcknots/wallet/verifier/plugins/ps384"
	"github.com/trustknots/vcknots/wallet/verifier/plugins/ps512"
	"github.com/trustknots/vcknots/wallet/verifier/plugins/rs256"
	"github.com/trustknots/vcknots/wallet/verifier/plugins/rs384"
	"github.com/trustknots/vcknots/wallet/verifier/plugins/rs512"
	"github.com/trustknots/vcknots/wallet/verifier/types"
)

// VerificationDispatcher implements the main verification interface with algorithm dispatching
type VerificationDispatcher struct {
	plugins map[jose.SignatureAlgorithm]types.VerificationComponent
	mu      sync.RWMutex
}

// NewVerificationDispatcher creates a new verification dispatcher
func NewVerificationDispatcher(options ...func(*VerificationDispatcher) error) (*VerificationDispatcher, error) {
	d := &VerificationDispatcher{
		plugins: make(map[jose.SignatureAlgorithm]types.VerificationComponent),
	}

	for _, option := range options {
		if err := option(d); err != nil {
			return nil, fmt.Errorf("failed to configure verification dispatcher: %w", err)
		}
	}

	return d, nil
}

// WithDefaultConfig registers a bundled verifier for every algorithm in
// commonJOSE.AcceptedSignatureAlgorithms: ES256/ES384/ES512 (RFC 7518 Section
// 3.4), RS256/RS384/RS512 and PS256/PS384/PS512 (Sections 3.3 and 3.5) and
// EdDSA over Ed25519 (RFC 8037). "none" and the MAC algorithms are never
// registered.
//
// Registering a plugin makes an algorithm verifiable, not acceptable. The
// credential acceptance path and Wallet.VerifyCredential apply their own
// algorithm policy (acceptance.Policy.SigningAlgorithms, ES256 by
// default); a caller of VerificationDispatcher.Verify gets every registered
// algorithm.
func WithDefaultConfig() func(*VerificationDispatcher) error {
	return func(d *VerificationDispatcher) error {
		for _, algorithm := range commonJOSE.AcceptedSignatureAlgorithms() {
			component := bundledVerifier(algorithm)
			if component == nil {
				return types.NewVerificationError(algorithm, "no bundled verifier", types.ErrPluginNotFound)
			}
			if err := d.RegisterPlugin(algorithm, component); err != nil {
				return err
			}
		}
		return nil
	}
}

// bundledVerifier returns the bundled plugin for algorithm, or nil.
func bundledVerifier(algorithm jose.SignatureAlgorithm) types.VerificationComponent {
	switch algorithm {
	case jose.ES256:
		return es256.NewES256Verifier()
	case jose.ES384:
		return es384.NewES384Verifier()
	case jose.ES512:
		return es512.NewES512Verifier()
	case jose.RS256:
		return rs256.NewRS256Verifier()
	case jose.RS384:
		return rs384.NewRS384Verifier()
	case jose.RS512:
		return rs512.NewRS512Verifier()
	case jose.PS256:
		return ps256.NewPS256Verifier()
	case jose.PS384:
		return ps384.NewPS384Verifier()
	case jose.PS512:
		return ps512.NewPS512Verifier()
	case jose.EdDSA:
		return eddsa.NewEdDSAVerifier()
	default:
		return nil
	}
}

// WithPlugin is an option function to register a custom verification component
func WithPlugin(algorithm jose.SignatureAlgorithm, component types.VerificationComponent) func(*VerificationDispatcher) error {
	return func(d *VerificationDispatcher) error {
		return d.RegisterPlugin(algorithm, component)
	}
}

// RegisterPlugin registers a verification component for a specific algorithm
func (d *VerificationDispatcher) RegisterPlugin(algorithm jose.SignatureAlgorithm, component types.VerificationComponent) error {
	if component == nil {
		return types.NewVerificationError(algorithm, "cannot register nil plugin", types.ErrNilPlugin)
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	d.plugins[algorithm] = component
	return nil
}

// getPlugin returns the verification component for the given algorithm
func (d *VerificationDispatcher) getPlugin(algorithm jose.SignatureAlgorithm) (types.VerificationComponent, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	plugin, exists := d.plugins[algorithm]
	if !exists {
		return nil, types.NewVerificationError(algorithm, "plugin not found", types.ErrPluginNotFound)
	}
	return plugin, nil
}

// Verify verifies a credential using the appropriate algorithm-specific component
func (d *VerificationDispatcher) Verify(proof *credential.CredentialProof, publicKey *jose.JSONWebKey) (bool, error) {
	if publicKey == nil {
		return false, types.NewVerificationError(proof.Algorithm, "public key cannot be nil", types.ErrInvalidPublicKey)
	}

	component, err := d.getPlugin(proof.Algorithm)
	if err != nil {
		return false, err
	}

	return component.Verify(proof, publicKey)
}

// GetSupportedAlgorithms returns a list of supported algorithms
func (d *VerificationDispatcher) GetSupportedAlgorithms() []jose.SignatureAlgorithm {
	d.mu.RLock()
	defer d.mu.RUnlock()

	algorithms := make([]jose.SignatureAlgorithm, 0, len(d.plugins))
	for alg := range d.plugins {
		algorithms = append(algorithms, alg)
	}
	return algorithms
}
