package wallet

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/trustknots/vcknots/wallet/experimental"
	idprofTypes "github.com/trustknots/vcknots/wallet/idprof/types"
	"github.com/trustknots/vcknots/wallet/internal/jwtproof"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// applyProofContent runs the Content hook of t on content.
func applyProofContent(t experimental.ProofTransform, content experimental.ProofJWTContent) (experimental.ProofJWTContent, error) {
	if t.Content == nil {
		return content, nil
	}
	transformed, err := t.Content(content)
	if err != nil {
		return experimental.ProofJWTContent{}, fmt.Errorf("%w: %w", ErrDraft13ProofTransformFailed, err)
	}
	if transformed.Header == nil {
		transformed.Header = map[string]any{}
	}
	if transformed.Claims == nil {
		transformed.Claims = map[string]any{}
	}
	return transformed, nil
}

// applyProofSerialized runs the Serialized hook of t on proof.
func applyProofSerialized(t experimental.ProofTransform, proof string) (string, error) {
	if t.Serialized == nil {
		return proof, nil
	}
	transformed, err := t.Serialized(proof)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrDraft13ProofTransformFailed, err)
	}
	return transformed, nil
}

type credentialRequestProofBindingMethod string

const (
	credentialRequestProofBindingMethodKID credentialRequestProofBindingMethod = "kid"
	credentialRequestProofBindingMethodJWK credentialRequestProofBindingMethod = "jwk"
)

// resolveCredentialRequestProofBindingMethod selects how the key proof names
// the key the credential is bound to (Draft 13 Section 7.2.1.1: kid, a DID
// URL, or jwk, never both) from the configuration's
// cryptographic_binding_methods_supported, taken in the issuer's order: the
// first method the wallet can produce, jwk or did:key. A configuration that
// lists none takes a did:key kid, which binds a W3C VC through its subject DID
// and an SD-JWT VC through the key. A list with no method the wallet can
// produce (did:web, cose_key, ...) is ErrCryptographicBindingMethodUnsupported:
// a proof by any other method would bind the credential to a key the issuer
// does not accept.
func resolveCredentialRequestProofBindingMethod(credentialConfiguration *receiverTypes.CredentialConfiguration) (credentialRequestProofBindingMethod, error) {
	if credentialConfiguration == nil || credentialConfiguration.CryptographicBindingMethodsSupported == nil || len(*credentialConfiguration.CryptographicBindingMethodsSupported) == 0 {
		return credentialRequestProofBindingMethodKID, nil
	}
	methods := *credentialConfiguration.CryptographicBindingMethodsSupported
	for _, method := range methods {
		switch strings.TrimSpace(method) {
		case string(credentialRequestProofBindingMethodJWK):
			return credentialRequestProofBindingMethodJWK, nil
		case "did:key":
			return credentialRequestProofBindingMethodKID, nil
		}
	}
	return "", fmt.Errorf("%w: cryptographic_binding_methods_supported %v", ErrCryptographicBindingMethodUnsupported, methods)
}

// draft13ProofRequired reports whether a Draft 13 Credential Request must
// carry a key proof: Section 7.2 makes it "REQUIRED if the
// proof_types_supported parameter is non-empty and present" for the
// configuration, and a configuration that lists binding methods binds the
// credential to the key the proof names.
func draft13ProofRequired(config receiverTypes.CredentialConfiguration) bool {
	return (config.ProofTypesSupported != nil && len(*config.ProofTypesSupported) > 0) || configurationRequiresBinding(config)
}

// proofJWTContent builds the header and claims of a "jwt" key proof (Draft 13
// Section 7.2.1.1). keyID is the kid of a kid-bound proof; a jwk-bound proof
// carries the public key instead.
func proofJWTContent(key IKeyEntry, keyID string, nonce *string, aud string, clientID *string, binding credentialRequestProofBindingMethod, now time.Time) (experimental.ProofJWTContent, error) {
	header := map[string]any{"typ": jwtproof.TypeKeyProof}
	if binding == credentialRequestProofBindingMethodJWK {
		alg, err := jwtproof.Algorithm(key)
		if err != nil {
			return experimental.ProofJWTContent{}, err
		}
		public, err := jwtproof.PublicJWK(key.PublicKey(), alg)
		if err != nil {
			return experimental.ProofJWTContent{}, err
		}
		header["jwk"] = public
	} else {
		if strings.TrimSpace(keyID) == "" {
			return experimental.ProofJWTContent{}, fmt.Errorf("a key identifier is required for kid proof binding")
		}
		header["kid"] = keyID
	}
	claims := map[string]any{"iat": now.Unix(), "aud": aud}
	if clientID != nil {
		if strings.TrimSpace(*clientID) == "" {
			return experimental.ProofJWTContent{}, fmt.Errorf("clientID must be non-empty when provided")
		}
		claims["iss"] = *clientID
	}
	if nonce != nil && *nonce != "" {
		claims["nonce"] = *nonce
	}
	return experimental.ProofJWTContent{Header: header, Claims: claims}, nil
}

// generateJWTProofWithTransform builds a key proof and passes it through
// transform. Without a DID a kid-bound proof cannot be built.
func (w *Wallet) generateJWTProofWithTransform(ctx context.Context, key IKeyEntry, keyID string, nonce *string, aud string, clientID *string, binding credentialRequestProofBindingMethod, transform experimental.ProofTransform) (string, error) {
	if key == nil {
		return "", ErrDraft13HolderKeyMissing
	}
	content, err := proofJWTContent(key, keyID, nonce, aud, clientID, binding, time.Now())
	if err != nil {
		return "", err
	}
	content, err = applyProofContent(transform, content)
	if err != nil {
		return "", err
	}
	proof, err := jwtproof.Sign(ctx, key, "", content.Header, content.Claims)
	if err != nil {
		return "", fmt.Errorf("failed to serialize JWT proof: %w", err)
	}
	return applyProofSerialized(transform, proof)
}

// didKeyVerificationMethod returns the DID URL of a did:key's one
// verification method (did:key Method Section 3.1.2): Draft 13 Section
// 7.2.1.1 requires the kid to identify a key, which the bare DID does not.
func didKeyVerificationMethod(did *idprofTypes.IdentityProfile) (string, error) {
	if did == nil || strings.TrimSpace(did.ID) == "" {
		return "", fmt.Errorf("did is required for kid proof binding")
	}
	identifier, ok := strings.CutPrefix(did.ID, "did:key:")
	if !ok || identifier == "" {
		return "", fmt.Errorf("did %q is not a did:key", did.ID)
	}
	if strings.Contains(did.ID, "#") {
		return did.ID, nil
	}
	return did.ID + "#" + identifier, nil
}

// ensureJWTProofSupported refuses a configuration whose proof_types_supported
// is empty or lacks jwt, the only key proof the wallet builds (Draft 13
// Section 7.2.1); one without proof_types_supported accepts any.
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
