package did

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/idprof/types"
)

// DIDKeyPlugin implements the DIDMethodPlugin interface for did:key method
type DIDKeyPlugin struct{}

// WithMethod sets the DID method
func WithMethod(method string) types.CreateOption {
	return func(config *types.CreateConfig) error {
		config.Set("method", method)
		return nil
	}
}

// WithPublicKey sets the public key for DID key creation
func WithPublicKey(key *jose.JSONWebKey) types.CreateOption {
	return func(config *types.CreateConfig) error {
		if key == nil {
			return fmt.Errorf("public key cannot be nil")
		}
		config.Set("publicKey", key)
		return nil
	}
}

// Create implements the DIDMethodPlugin interface
func (p *DIDKeyPlugin) Create(opts ...types.CreateOption) (*types.IdentityProfile, error) {
	// Build configuration from options
	config := types.NewCreateConfig()
	for _, opt := range opts {
		if err := opt(config); err != nil {
			return nil, fmt.Errorf("failed to apply create option: %w", err)
		}
	}

	// Extract public key from configuration
	pubKeyParam, exists := config.Get("publicKey")
	if !exists {
		return nil, fmt.Errorf("publicKey parameter is required for did:key creation")
	}

	pubKey, ok := pubKeyParam.(*jose.JSONWebKey)
	if !ok {
		return nil, fmt.Errorf("publicKey parameter must be a *jose.JSONWebKey")
	}

	// Create the DID key profile
	createOpts := &DIDKeyProfileCreateOptions{
		DIDProfileCreateOptions: DIDProfileCreateOptions{Method: "key"},
		PublicKey:               pubKey,
	}

	didKeyProfile, err := NewDIDKeyProfile(createOpts)
	if err != nil {
		return nil, err
	}

	// Convert DIDKeyProfile to IdentityProfile
	return &didKeyProfile.DIDProfile.IdentityProfile, nil
}

// Resolve resolves a did:key identifier to an IdentityProfile
// For did:key, the key material is encoded in the identifier itself, so resolution is deterministic
func (p *DIDKeyPlugin) Resolve(id string) (*types.IdentityProfile, error) {
	if !strings.HasPrefix(id, "did:key:") {
		return nil, fmt.Errorf("invalid did:key format: %s", id)
	}

	// Extract the multibase-encoded public key from the DID
	encoded := strings.TrimPrefix(id, "did:key:z")
	if len(encoded) == 0 {
		return nil, fmt.Errorf("invalid did:key format: missing encoded key")
	}

	// Decode the multibase-encoded key
	decoded := base58.Decode(encoded)
	if len(decoded) == 0 {
		return nil, fmt.Errorf("failed to decode multibase key from DID")
	}

	// Parse the multicodec-encoded key
	keyBytes, codecType, err := decodeMulticodec(decoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode multicodec: %w", err)
	}

	jwk, err := didKeyPublicJWK(codecType, keyBytes)
	if err != nil {
		return nil, err
	}
	jwk.KeyID = id
	jwk.Use = "sig"

	return &types.IdentityProfile{
		ID:     id,
		TypeID: "did:key",
		Keys: &jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{jwk},
		},
	}, nil
}

// didKeyPublicJWK decodes the public key a did:key identifier carries. The
// did:key method names the key type with a multicodec; this library supports
// P-256 (0x1200) and Ed25519 (0xed).
func didKeyPublicJWK(codecType uint64, keyBytes []byte) (jose.JSONWebKey, error) {
	switch codecType {
	case P256Pub:
		pubKey, err := parseCompressedP256Key(keyBytes)
		if err != nil {
			return jose.JSONWebKey{}, fmt.Errorf("failed to parse P256 key: %w", err)
		}
		return jose.JSONWebKey{Key: pubKey, Algorithm: string(jose.ES256)}, nil
	case Ed25519Pub:
		if len(keyBytes) != ed25519.PublicKeySize {
			return jose.JSONWebKey{}, fmt.Errorf("failed to parse Ed25519 key: %d bytes, want %d", len(keyBytes), ed25519.PublicKeySize)
		}
		return jose.JSONWebKey{Key: ed25519.PublicKey(append([]byte(nil), keyBytes...)), Algorithm: string(jose.EdDSA)}, nil
	default:
		return jose.JSONWebKey{}, fmt.Errorf("unsupported key type: %d", codecType)
	}
}

// Update updates a did:key profile
// Note: did:key profiles are immutable by design, so this operation is not supported
func (p *DIDKeyPlugin) Update(profile *types.IdentityProfile, opts ...types.UpdateOption) (*types.IdentityProfile, error) {
	return nil, fmt.Errorf("did:key profiles are immutable and cannot be updated")
}

// Validate validates a did:key profile
func (p *DIDKeyPlugin) Validate(profile *types.IdentityProfile) error {
	if profile == nil {
		return fmt.Errorf("profile cannot be nil")
	}

	if profile.TypeID != "did:key" {
		return fmt.Errorf("invalid type ID for did:key profile: %s", profile.TypeID)
	}

	if !strings.HasPrefix(profile.ID, "did:key:") {
		return fmt.Errorf("invalid did:key format: %s", profile.ID)
	}

	if profile.Keys == nil || len(profile.Keys.Keys) == 0 {
		return fmt.Errorf("did:key profile must have at least one key")
	}

	// Verify that the key in the profile matches the one encoded in the DID
	resolvedProfile, err := p.Resolve(profile.ID)
	if err != nil {
		return fmt.Errorf("failed to resolve DID for validation: %w", err)
	}

	if len(profile.Keys.Keys) != len(resolvedProfile.Keys.Keys) {
		return fmt.Errorf("key count mismatch")
	}

	// Compare the first key (did:key typically has only one key)
	profileKey := profile.Keys.Keys[0]
	resolvedKey := resolvedProfile.Keys.Keys[0]

	if profileKey.Algorithm != resolvedKey.Algorithm {
		return fmt.Errorf("key algorithm mismatch")
	}

	// Compare the actual key material
	resolvedPubKey, ok := resolvedKey.Key.(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return fmt.Errorf("resolved key is not a comparable public key")
	}
	if !resolvedPubKey.Equal(profileKey.Key) {
		return fmt.Errorf("key material does not match DID identifier")
	}

	return nil
}

// DIDKeyProfile is a DID profile for the did:key method.
type DIDKeyProfile struct {
	DIDProfile
}

// DIDKeyProfileCreateOptions holds the options for NewDIDKeyProfile.
type DIDKeyProfileCreateOptions struct {
	DIDProfileCreateOptions
	PublicKey *jose.JSONWebKey
}

// NewDIDKeyProfile returns the did:key profile of opts.PublicKey, which must be a
// P-256 or Ed25519 public key. The key is the profile's only key.
func NewDIDKeyProfile(opts *DIDKeyProfileCreateOptions) (*DIDKeyProfile, error) {
	if opts.PublicKey == nil {
		return nil, fmt.Errorf("public key is required to create a DIDKeyProfile")
	}

	if opts.PublicKey.Key == nil {
		return nil, fmt.Errorf("public key is required in the JSON Web Key")
	}

	encoded, err := didKeyFingerprint(opts.PublicKey.Key)
	if err != nil {
		return nil, err
	}

	if len(encoded) == 0 {
		return nil, fmt.Errorf("encoded public key cannot be empty")
	}

	p := &DIDKeyProfile{
		DIDProfile: DIDProfile{
			IdentityProfile: types.IdentityProfile{
				ID:     fmt.Sprintf("did:key:z%s", encoded),
				TypeID: "did:key",
				Keys: &jose.JSONWebKeySet{
					Keys: []jose.JSONWebKey{*opts.PublicKey},
				},
			},
			Method: "key",
		},
	}

	return p, nil
}

// didKeyFingerprint returns the base58-btc encoding of the multicodec-prefixed
// public key that follows "did:key:z".
func didKeyFingerprint(key any) (string, error) {
	switch pubKey := key.(type) {
	case *ecdsa.PublicKey:
		if pubKey.Curve != elliptic.P256() {
			return "", fmt.Errorf("only P256 curve is supported for DIDKeyProfile")
		}
		return base58.Encode(encodeMulticodec(P256Pub, elliptic.MarshalCompressed(elliptic.P256(), pubKey.X, pubKey.Y))), nil
	case ed25519.PublicKey:
		if len(pubKey) != ed25519.PublicKeySize {
			return "", fmt.Errorf("invalid Ed25519 public key size %d", len(pubKey))
		}
		return base58.Encode(encodeMulticodec(Ed25519Pub, pubKey)), nil
	default:
		return "", fmt.Errorf("public key must be a P-256 ecdsa.PublicKey or an ed25519.PublicKey")
	}
}

// ToDIDProfile converts DIDKeyProfile to DIDProfile
func (p *DIDKeyProfile) ToDIDProfile() *DIDProfile {
	return &p.DIDProfile
}

// Limits of the multiformats unsigned varint encoding.
const (
	// MaxLenUvarint63 is the maximum length in bytes of an unsigned varint.
	MaxLenUvarint63 = 9
	// MaxValueUvarint63 is the largest value an unsigned varint may encode.
	MaxValueUvarint63 = (1 << 63) - 1
)

// Multicodec codes of the public key types did:key supports.
const (
	// P256Pub is the multicodec code of a compressed P-256 public key.
	P256Pub = 0x1200
	// Ed25519Pub is the multicodec code of an Ed25519 public key.
	Ed25519Pub = 0xed
)

// decodeMulticodec decodes a multicodec-encoded byte slice
func decodeMulticodec(multicodec []byte) ([]byte, uint64, error) {
	code, n := binary.Uvarint(multicodec)
	if n <= 0 {
		return nil, 0, fmt.Errorf("invalid multicodec; varint overflow")
	}

	return multicodec[n:], code, nil
}

// parseCompressedP256Key parses a compressed P256 public key
func parseCompressedP256Key(keyBytes []byte) (*ecdsa.PublicKey, error) {
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), keyBytes)
	if x == nil || y == nil {
		return nil, fmt.Errorf("failed to parse compressed P256 key")
	}

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}, nil
}

func encodeMulticodec(code uint64, bytes []byte) []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(buf, code)
	return append(buf[:n], bytes...)
}
