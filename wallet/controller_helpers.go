package wallet

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/trustknots/vcknots/wallet/credstore/types"
	idprofTypes "github.com/trustknots/vcknots/wallet/idprof/types"
)

// convertEntryToSavedCredential converts a CredentialEntry to SavedCredential.
// Returns error if conversion fails (invalid flavor or deserialization error).
func (c *Controller) convertEntryToSavedCredential(entry types.CredentialEntry) (*SavedCredential, error) {
	f, err := entry.SerializationFlavor()
	if err != nil {
		return nil, fmt.Errorf("invalid serialization flavor: %w", err)
	}

	cred, err := c.serializer.DeserializeCredential(f, entry.Raw)
	if err != nil {
		return nil, fmt.Errorf("deserialization failed: %w", err)
	}

	return &SavedCredential{
		Credential: cred,
		Entry:      &entry,
	}, nil
}

// generateJWTProof generates a JWT proof for credential requests.
func (c *Controller) generateJWTProof(key IKeyEntry, did *idprofTypes.IdentityProfile, nonce *string, aud string) (string, error) {
	header := map[string]interface{}{
		"alg": "ES256",
		"typ": "JWT",
		"kid": did.ID,
	}

	payload := map[string]interface{}{
		"iss": did.ID,
		"iat": time.Now().Unix(),
		"aud": aud,
	}

	if nonce != nil && *nonce != "" {
		payload["nonce"] = *nonce
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	b64Header := base64.RawURLEncoding.EncodeToString(headerJSON)
	b64Payload := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signingInput := b64Header + "." + b64Payload
	signature, err := key.Sign([]byte(signingInput))
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	b64Signature := base64.RawURLEncoding.EncodeToString(signature)
	return signingInput + "." + b64Signature, nil
}
