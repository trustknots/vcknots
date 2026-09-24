package wallet

import (
	"context"
	"fmt"
	"strings"
	"time"

	idprofTypes "github.com/trustknots/vcknots/wallet/idprof/types"
	"github.com/trustknots/vcknots/wallet/internal/jwtproof"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// ProofJWTContent is the header and claims of a key proof before it is
// signed. Both maps are copies a transform may change. Header never carries
// "alg": the algorithm belongs to the signing key.
type ProofJWTContent struct {
	Header map[string]any
	Claims map[string]any
}

// ProofTransform rewrites a Draft 13 key proof, for testing how an issuer
// handles a malformed one. Content runs before signing, so the result is
// still correctly signed; Serialized runs on the compact JWS. A nil member is
// not called, so the zero value leaves the proof unchanged. An error aborts
// the issuance with ErrDraft13ProofTransformFailed.
type ProofTransform struct {
	Content    func(ProofJWTContent) (ProofJWTContent, error)
	Serialized func(string) (string, error)
}

func (t ProofTransform) applyContent(content ProofJWTContent) (ProofJWTContent, error) {
	if t.Content == nil {
		return content, nil
	}
	transformed, err := t.Content(content)
	if err != nil {
		return ProofJWTContent{}, fmt.Errorf("%w: %w", ErrDraft13ProofTransformFailed, err)
	}
	if transformed.Header == nil {
		transformed.Header = map[string]any{}
	}
	if transformed.Claims == nil {
		transformed.Claims = map[string]any{}
	}
	return transformed, nil
}

func (t ProofTransform) applySerialized(proof string) (string, error) {
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

// resolveCredentialRequestProofBindingMethod binds the key proof by kid (a
// DID URL) unless the configuration lists jwk before any DID method.
func resolveCredentialRequestProofBindingMethod(credentialConfiguration *receiverTypes.CredentialConfiguration) credentialRequestProofBindingMethod {
	if credentialConfiguration == nil {
		return credentialRequestProofBindingMethodKID
	}
	format := strings.ToLower(strings.TrimSpace(credentialConfiguration.Format))
	if format == "jwt_vc_json" || format == "jwt_vc" || credentialConfiguration.CryptographicBindingMethodsSupported == nil {
		return credentialRequestProofBindingMethodKID
	}
	for _, method := range *credentialConfiguration.CryptographicBindingMethodsSupported {
		normalized := strings.ToLower(strings.TrimSpace(method))
		if strings.HasPrefix(normalized, "did:") {
			return credentialRequestProofBindingMethodKID
		}
		if normalized == string(credentialRequestProofBindingMethodJWK) {
			return credentialRequestProofBindingMethodJWK
		}
	}
	return credentialRequestProofBindingMethodKID
}

// proofJWTContent builds the header and claims of a "jwt" key proof (Draft 13
// Section 7.2.1.1). keyID is the kid of a kid-bound proof; a jwk-bound proof
// carries the public key instead.
func proofJWTContent(key IKeyEntry, keyID string, nonce *string, aud string, clientID *string, binding credentialRequestProofBindingMethod, now time.Time) (ProofJWTContent, error) {
	header := map[string]any{"typ": jwtproof.TypeKeyProof}
	if binding == credentialRequestProofBindingMethodJWK {
		alg, err := jwtproof.Algorithm(key)
		if err != nil {
			return ProofJWTContent{}, err
		}
		public, err := jwtproof.PublicJWK(key.PublicKey(), alg)
		if err != nil {
			return ProofJWTContent{}, err
		}
		header["jwk"] = public
	} else {
		if strings.TrimSpace(keyID) == "" {
			return ProofJWTContent{}, fmt.Errorf("a key identifier is required for kid proof binding")
		}
		header["kid"] = keyID
	}
	claims := map[string]any{"iat": now.Unix(), "aud": aud}
	if clientID != nil {
		if strings.TrimSpace(*clientID) == "" {
			return ProofJWTContent{}, fmt.Errorf("clientID must be non-empty when provided")
		}
		claims["iss"] = *clientID
	}
	if nonce != nil && *nonce != "" {
		claims["nonce"] = *nonce
	}
	return ProofJWTContent{Header: header, Claims: claims}, nil
}

// generateJWTProofWithTransform builds a key proof and passes it through
// transform. Without a DID a kid-bound proof cannot be built.
func (w *Wallet) generateJWTProofWithTransform(ctx context.Context, key IKeyEntry, keyID string, nonce *string, aud string, clientID *string, binding credentialRequestProofBindingMethod, transform ProofTransform) (string, error) {
	if key == nil {
		return "", ErrDraft13HolderKeyMissing
	}
	content, err := proofJWTContent(key, keyID, nonce, aud, clientID, binding, time.Now())
	if err != nil {
		return "", err
	}
	content, err = transform.applyContent(content)
	if err != nil {
		return "", err
	}
	proof, err := jwtproof.Sign(ctx, key, "", content.Header, content.Claims)
	if err != nil {
		return "", fmt.Errorf("failed to serialize JWT proof: %w", err)
	}
	return transform.applySerialized(proof)
}

// generateJWTProof builds an untransformed key proof; a kid-bound proof is
// bound to did.ID.
func (w *Wallet) generateJWTProof(key IKeyEntry, did *idprofTypes.IdentityProfile, nonce *string, aud string, clientID *string, binding credentialRequestProofBindingMethod) (string, error) {
	keyID := ""
	if binding != credentialRequestProofBindingMethodJWK {
		if did == nil {
			return "", fmt.Errorf("did is required for kid proof binding")
		}
		if strings.TrimSpace(did.ID) == "" {
			return "", fmt.Errorf("did.ID is required for kid proof binding")
		}
		keyID = did.ID
	}
	return w.generateJWTProofWithTransform(context.Background(), key, keyID, nonce, aud, clientID, binding, ProofTransform{})
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
