// Package jwks provides support for JSON Web Key Set (JWKS) based identity profiles
package jwks

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/idprof/types"
)

const IDProfileTypeID = "jwks"

// JWKSPlugin implements the IdentityProfiler interface for JWKS-based profiles
type JWKSPlugin struct {
	httpClient *http.Client
}

// JWKSProfileCreateOptions contains options for creating a JWKS profile
type JWKSProfileCreateOptions struct {
	// URL is the JWKS endpoint URL
	URL string
	// Keys can be provided directly instead of fetching from URL
	Keys *jose.JSONWebKeySet
}

// JWKSProfileUpdateOptions contains options for updating a JWKS profile
type JWKSProfileUpdateOptions struct {
	// URL is the new JWKS endpoint URL (optional)
	URL string
	// Keys can be provided directly to update the keyset
	Keys *jose.JSONWebKeySet
}

// NewJWKSPlugin creates a new JWKS plugin
func NewJWKSPlugin() *JWKSPlugin {
	return &JWKSPlugin{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// NewJWKSPluginWithClient creates a new JWKS plugin with a custom HTTP client
func NewJWKSPluginWithClient(client *http.Client) (*JWKSPlugin, error) {
	if client == nil {
		return nil, fmt.Errorf("client should not be nil")
	}
	return &JWKSPlugin{
		httpClient: client,
	}, nil
}

// Create creates a new JWKS-based identity profile
func (p *JWKSPlugin) Create(opts ...types.CreateOption) (*types.IdentityProfile, error) {
	// Basically, JWK cannot be created but resolved, since standard operation API does not exist.
	return nil, fmt.Errorf("cannot create JWKS profile")
}

// Resolve resolves a JWKS profile from its URL
func (p *JWKSPlugin) Resolve(id string) (*types.IdentityProfile, error) {
	// Validate URL format
	if _, err := url.Parse(id); err != nil {
		return nil, fmt.Errorf("invalid JWKS URL: %s", id)
	}

	keys, err := p.fetchJWKS(id)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS from %s: %w", id, err)
	}

	return &types.IdentityProfile{
		ID:     id,
		TypeID: IDProfileTypeID,
		Keys:   keys,
	}, nil
}

// Update updates a JWKS profile
func (p *JWKSPlugin) Update(profile *types.IdentityProfile, opts ...types.UpdateOption) (*types.IdentityProfile, error) {
	// JWKS profiles are immutable, so we cannot update them.
	return nil, fmt.Errorf("JWKS profiles cannot be updated")
}

// Validate validates a JWKS profile
func (p *JWKSPlugin) Validate(profile *types.IdentityProfile) error {
	if profile == nil {
		return fmt.Errorf("profile cannot be nil")
	}

	if profile.TypeID != IDProfileTypeID {
		return fmt.Errorf("invalid type ID for JWKS profile: %s", profile.TypeID)
	}

	if profile.Keys == nil || len(profile.Keys.Keys) == 0 {
		return fmt.Errorf("JWKS profile must have at least one key")
	}

	// Validate each key in the set
	for i, key := range profile.Keys.Keys {
		if !key.Valid() {
			return fmt.Errorf("invalid key at index %d", i)
		}
	}

	return nil
}

// GetTypeID returns the type identifier for JWKS profiles
func (p *JWKSPlugin) GetTypeID() string {
	return IDProfileTypeID
}

// fetchJWKS fetches a JWKS from the given URL
func (p *JWKSPlugin) fetchJWKS(jwksURL string) (*jose.JSONWebKeySet, error) {
	if p.httpClient == nil {
		return nil, fmt.Errorf("failed to fetch JWKS: httpClient is nil")
	}
	resp, err := p.httpClient.Get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWKS response: %w", err)
	}

	var jwks jose.JSONWebKeySet
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS JSON: %w", err)
	}

	return &jwks, nil
}
