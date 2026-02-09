package did

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/idprof/types"
)

func newTestKeyPluginProfile(t *testing.T) (*DIDKeyPlugin, *types.IdentityProfile) {
	t.Helper()
	plugin := &DIDKeyPlugin{}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}
	publicKeyJWK := &jose.JSONWebKey{
		Key:       &privateKey.PublicKey,
		Algorithm: string(jose.ES256),
	}

	profile, err := plugin.Create(WithPublicKey(publicKeyJWK))
	if err != nil {
		t.Fatalf("Failed to create profile for test setup: %v", err)
	}
	return plugin, profile
}

// Existing tests

func TestDIDKeyPlugin_Create(t *testing.T) {
	plugin := &DIDKeyPlugin{}
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	publicKeyJWK := &jose.JSONWebKey{Key: &privateKey.PublicKey, Algorithm: string(jose.ES256)}

	t.Run("Happy path", func(t *testing.T) {
		profile, err := plugin.Create(WithPublicKey(publicKeyJWK))
		if err != nil {
			t.Errorf("Create() should not return error: %v", err)
		}
		if !strings.HasPrefix(profile.ID, "did:key:z") {
			t.Errorf("expected DID to start with 'did:key:z', got '%s'", profile.ID)
		}
	})

	t.Run("Missing public key", func(t *testing.T) {
		_, err := plugin.Create()
		if err == nil {
			t.Error("Create() should return error when public key is missing")
		}
	})

	t.Run("Option function fails", func(t *testing.T) {
		failingOption := func(c *types.CreateConfig) error {
			return errors.New("option failed")
		}
		_, err := plugin.Create(failingOption)
		if err == nil {
			t.Error("Create() should return error when an option fails")
		}
	})

	t.Run("Public key is wrong type", func(t *testing.T) {
		wrongTypeOption := func(c *types.CreateConfig) error {
			c.Set("publicKey", "not-a-jwk")
			return nil
		}
		_, err := plugin.Create(wrongTypeOption)
		if err == nil {
			t.Error("Create() should return error when publicKey is not a *jose.JSONWebKey")
		}
	})
}

func TestNewDIDKeyProfile(t *testing.T) {
	t.Run("Public key is not ECDSA", func(t *testing.T) {
		notEcdsaKey := &jose.JSONWebKey{Key: "not-an-ecdsa-key"}
		opts := &DIDKeyProfileCreateOptions{PublicKey: notEcdsaKey}
		_, err := NewDIDKeyProfile(opts)
		if err == nil {
			t.Error("NewDIDKeyProfile() should return error for non-ecdsa public key")
		}
	})

	t.Run("Unsupported curve", func(t *testing.T) {
		p384Key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		unsupportedKey := &jose.JSONWebKey{Key: &p384Key.PublicKey}
		opts := &DIDKeyProfileCreateOptions{PublicKey: unsupportedKey}
		_, err := NewDIDKeyProfile(opts)
		if err == nil {
			t.Error("NewDIDKeyProfile() should return error for unsupported curve")
		}
	})
}

// Additional Test

func TestDIDKeyPlugin_Resolve(t *testing.T) {
	plugin, profile := newTestKeyPluginProfile(t)

	t.Run("Happy path", func(t *testing.T) {
		resolved, err := plugin.Resolve(profile.ID)
		if err != nil {
			t.Fatalf("Resolve() failed: %v", err)
		}
		if resolved.ID != profile.ID {
			t.Errorf("resolved ID mismatch: got %s, want %s", resolved.ID, profile.ID)
		}
	})

	t.Run("Error cases", func(t *testing.T) {
		overflowingVarint := []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01}
		testCases := []struct {
			name    string
			did     string
			wantErr string
		}{
			{"invalid prefix", "did:other:123", "invalid did:key format"},
			{"empty key", "did:key:z", "missing encoded key"},
			{"bad base58", "did:key:z00000", "failed to decode multibase key"},
			{"varint overflow", "did:key:z" + base58.Encode(overflowingVarint), "unsupported key type"},
			{"unsupported key type", "did:key:z" + base58.Encode(encodeMulticodec(0x1100, []byte("key"))), "unsupported key type"},
			{"bad compressed key", "did:key:z" + base58.Encode(encodeMulticodec(P256Pub, []byte("bad-key"))), "failed to parse P256 key"},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := plugin.Resolve(tc.did)
				if err == nil {
					t.Errorf("Resolve() with %s should have failed, but did not", tc.name)
				} else if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("Resolve() error mismatch: got '%v', want to contain '%s'", err, tc.wantErr)
				}
			})
		}
	})
}

func TestDIDKeyPlugin_Update(t *testing.T) {
	plugin, profile := newTestKeyPluginProfile(t)
	_, err := plugin.Update(profile)
	if err == nil {
		t.Fatal("Update() should always return an error for did:key")
	}
	if !strings.Contains(err.Error(), "immutable") {
		t.Errorf("expected immutable error, got %v", err)
	}
}

func TestDIDKeyPlugin_Validate(t *testing.T) {
	plugin, profile := newTestKeyPluginProfile(t)

	t.Run("Happy path", func(t *testing.T) {
		err := plugin.Validate(profile)
		if err != nil {
			t.Errorf("Validate() on a valid profile failed: %v", err)
		}
	})

	t.Run("Error cases", func(t *testing.T) {
		_, otherProfile := newTestKeyPluginProfile(t)
		invalidKeyProfile := &types.IdentityProfile{
			ID:     profile.ID,
			TypeID: "did:key",
			Keys:   otherProfile.Keys,
		}

		testCases := []struct {
			name    string
			profile *types.IdentityProfile
			wantErr string
		}{
			{"nil profile", nil, "profile cannot be nil"},
			{"invalid type id", &types.IdentityProfile{ID: profile.ID, TypeID: "did:other"}, "invalid type ID"},
			{"invalid did format", &types.IdentityProfile{ID: "not-a-did", TypeID: "did:key"}, "invalid did:key format"},
			{"nil keys", &types.IdentityProfile{ID: profile.ID, TypeID: "did:key", Keys: nil}, "must have at least one key"},
			{"key material mismatch", invalidKeyProfile, "key material does not match"},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				err := plugin.Validate(tc.profile)
				if err == nil {
					t.Errorf("Validate() with %s should have failed, but did not", tc.name)
				} else if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("Validate() error mismatch: got '%v', want to contain '%s'", err, tc.wantErr)
				}
			})
		}
	})
}
