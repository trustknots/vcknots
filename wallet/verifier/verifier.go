// Package verifier provides credential verification functionality with algorithm dispatching
package verifier

import (
	"fmt"
	"sync"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/verifier/plugins/es256"
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

// WithDefaultConfig is an option function to configure the dispatcher with built-in components
func WithDefaultConfig() func(*VerificationDispatcher) error {
	return func(d *VerificationDispatcher) error {
		// Register built-in verification components
		return d.RegisterPlugin(jose.ES256, es256.NewES256Verifier())
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
