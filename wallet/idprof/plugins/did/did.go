// Package did provides the implementation of decentralized identifiers (DIDs) and their associated profiles.
package did

import (
	"fmt"
	"strings"

	"github.com/trustknots/vcknots/wallet/idprof/types"
)

const IDProfileTypeID = "did"

type DIDProfile struct {
	types.IdentityProfile

	Method string // Method specifies the DID method, e.g., "key", "peer", etc.
}

type DIDProfileCreateOptions struct {
	// Method specifies the DID method to be used for the profile.
	Method string // e.g., "key", "peer", etc.
}

type DIDMethod int

const (
	DIDMethodKey DIDMethod = iota // did:key
)

// DIDPlugin implements the IdentityProfilePlugin interface for DID profiles
type DIDPlugin struct {
	methodPlugins map[string]DIDMethodPlugin
}

// DIDMethodPlugin defines the interface for DID method-specific plugins
type DIDMethodPlugin interface {
	Create(opts ...types.CreateOption) (*types.IdentityProfile, error)
	Resolve(id string) (*types.IdentityProfile, error)
	Update(profile *types.IdentityProfile, opts ...types.UpdateOption) (*types.IdentityProfile, error)
	Validate(profile *types.IdentityProfile) error
}

// NewDIDPlugin creates a new DID plugin
func NewDIDPlugin() *DIDPlugin {
	plugin := &DIDPlugin{
		methodPlugins: make(map[string]DIDMethodPlugin),
	}
	// Register built-in method plugins
	plugin.RegisterMethodPlugin("key", &DIDKeyPlugin{})
	return plugin
}

// RegisterMethodPlugin registers a method plugin for a specific DID method
func (p *DIDPlugin) RegisterMethodPlugin(method string, plugin DIDMethodPlugin) {
	p.methodPlugins[method] = plugin
}

// getMethodPlugin returns the method plugin for the given DID method
func (p *DIDPlugin) getMethodPlugin(method string) (DIDMethodPlugin, error) {
	plugin, exists := p.methodPlugins[method]
	if !exists {
		return nil, fmt.Errorf("unsupported DID method: %s", method)
	}
	return plugin, nil
}

// Create implements the IdentityProfiler interface
func (p *DIDPlugin) Create(opts ...types.CreateOption) (*types.IdentityProfile, error) {
	// Build configuration from options
	config := types.NewCreateConfig()
	for _, opt := range opts {
		if err := opt(config); err != nil {
			return nil, fmt.Errorf("failed to apply create option: %w", err)
		}
	}

	// Extract method from configuration
	methodParam, exists := config.Get("method")
	if !exists {
		return nil, fmt.Errorf("method parameter is required")
	}
	
	method, ok := methodParam.(string)
	if !ok {
		return nil, fmt.Errorf("method parameter must be a string")
	}

	methodPlugin, err := p.getMethodPlugin(method)
	if err != nil {
		return nil, err
	}

	return methodPlugin.Create(opts...)
}

// Resolve resolves a DID document from its identifier
func (p *DIDPlugin) Resolve(id string) (*types.IdentityProfile, error) {
	// Extract method from DID (e.g., "did:key:..." -> "key")
	method, err := extractDIDMethod(id)
	if err != nil {
		return nil, fmt.Errorf("failed to extract DID method from %s: %w", id, err)
	}

	methodPlugin, err := p.getMethodPlugin(method)
	if err != nil {
		return nil, err
	}

	return methodPlugin.Resolve(id)
}

// Update updates a DID profile
func (p *DIDPlugin) Update(profile *types.IdentityProfile, opts ...types.UpdateOption) (*types.IdentityProfile, error) {
	if profile == nil {
		return nil, fmt.Errorf("profile cannot be nil")
	}

	// Extract method from DID
	method, err := extractDIDMethod(profile.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to extract DID method from %s: %w", profile.ID, err)
	}

	methodPlugin, err := p.getMethodPlugin(method)
	if err != nil {
		return nil, err
	}

	return methodPlugin.Update(profile, opts...)
}

// Validate validates a DID profile
func (p *DIDPlugin) Validate(profile *types.IdentityProfile) error {
	if profile == nil {
		return fmt.Errorf("profile cannot be nil")
	}

	// Extract method from DID
	method, err := extractDIDMethod(profile.ID)
	if err != nil {
		return fmt.Errorf("failed to extract DID method from %s: %w", profile.ID, err)
	}

	methodPlugin, err := p.getMethodPlugin(method)
	if err != nil {
		return err
	}

	return methodPlugin.Validate(profile)
}

// GetTypeID returns the type identifier for DID profiles
func (p *DIDPlugin) GetTypeID() string {
	return IDProfileTypeID
}

// extractDIDMethod extracts the method from a DID string
// e.g., "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK" -> "key"
func extractDIDMethod(did string) (string, error) {
	if len(did) < 4 || did[:4] != "did:" {
		return "", fmt.Errorf("invalid DID format: %s", did)
	}

	parts := strings.Split(did, ":")
	if len(parts) < 3 {
		return "", fmt.Errorf("invalid DID format: %s", did)
	}

	return parts[1], nil
}

// NewDIDProfile creates a new DID profile with the specified options.
func NewDIDProfile(typeID string, opts any) (*DIDProfile, error) {
	if typeID != IDProfileTypeID {
		return nil, fmt.Errorf("unsupported DID type ID: %s", typeID)
	}

	// First try method-specific options
	switch v := opts.(type) {
	case DIDKeyProfileCreateOptions:
		if v.Method == "key" {
			keyProfile, err := NewDIDKeyProfile(&v)
			if err != nil {
				return nil, err
			}
			return keyProfile.ToDIDProfile(), nil
		}
		return nil, fmt.Errorf("unsupported DID method: %s", v.Method)
	case DIDProfileCreateOptions:
		switch v.Method {
		case "key":
			// If only basic DID options provided, we can't create a key profile
			// because we need the public key
			return nil, fmt.Errorf("DID key method requires DIDKeyProfileCreateOptions with PublicKey")
		default:
			return nil, fmt.Errorf("unsupported DID method: %s", v.Method)
		}
	default:
		return nil, fmt.Errorf("invalid options type for DID profile creation")
	}
}
