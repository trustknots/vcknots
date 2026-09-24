package wallet

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/trustknots/vcknots/wallet/acceptance"
	"github.com/trustknots/vcknots/wallet/attestation"
	"github.com/trustknots/vcknots/wallet/credential"
	credstoreTypes "github.com/trustknots/vcknots/wallet/credstore/types"
	"github.com/trustknots/vcknots/wallet/idprof/plugins/did"
	"github.com/trustknots/vcknots/wallet/internal/jwtproof"
	receiverOid4vci "github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// RequestCredential sends the OpenID4VCI 1.0 Credential Request (Section 8)
// for grant with one key proof per holder key, a key attestation when the
// issuer requires one or the request includes one (Appendix D), and response
// encryption per Config.Issuance.CredentialEncryption with an ephemeral key.
// The credentials are verified under Config.CredentialAcceptance and saved
// unless the wallet is storeless.
//
// A key attestation that neither the request nor Config.Attestation.Key
// supplies stops the call before anything is sent, with
// *KeyAttestationRequiredError. A deferred issuance returns
// IssuanceResult.Deferred. Refused credentials are returned with the error and
// a result whose Notification lets the caller report credential_failure.
func (w *Wallet) RequestCredential(ctx context.Context, grant *IssuanceGrant, req CredentialRequest) (*IssuanceResult, error) {
	result, err := w.requestFinalCredential(ctx, grant, req)
	return result, classify(err)
}

func (w *Wallet) requestFinalCredential(ctx context.Context, grant *IssuanceGrant, req CredentialRequest) (*IssuanceResult, error) {
	if err := checkGrant(grant, IssuanceVersionFinal); err != nil {
		return nil, err
	}
	if err := w.requireFinalIssuance(ctx); err != nil {
		return nil, err
	}
	if err := w.checkGrantToken(grant.AccessToken); err != nil {
		return nil, err
	}
	dpopKey, err := w.requireDPoPKey(grant.DPoPKeyThumbprint, grant.AccessToken, fmt.Errorf("the access token is DPoP-bound but no DPoP key is configured: %w", ErrDPoPKeyMismatch))
	if err != nil {
		return nil, err
	}
	if err := checkHolderKeys(req.HolderKeys); err != nil {
		return nil, err
	}
	transport, err := w.oid4vciTransport()
	if err != nil {
		return nil, err
	}
	discovery, err := w.discoverIssuance(ctx, transport, grant.cache, grant.CredentialIssuer, pinnedAuthorizationServer(grant.AuthorizationServer), false)
	if err != nil {
		return nil, err
	}
	md := discovery.issuerMetadata
	config, err := w.finalCredentialConfiguration(transport, md, grant.CredentialConfigurationID)
	if err != nil {
		return nil, err
	}
	if len(req.HolderKeys) > md.BatchSize() {
		return nil, invalidArgument("requested %d credentials but the issuer batch_size is %d", len(req.HolderKeys), md.BatchSize())
	}
	signingAlgValues := proofSigningAlgValues(config)
	for index, key := range req.HolderKeys {
		if _, err := jwtproof.SelectAlgorithm(key, signingAlgValues); err != nil {
			return nil, fmt.Errorf("holder key %d: %w", index, err)
		}
	}

	decryptionKey, err := w.issuance.CredentialEncryption.responseEncryptionKey(md)
	if err != nil {
		return nil, err
	}
	encryption, err := receiverOid4vci.CredentialResponseEncryptionParameters(md, decryptionKey)
	if err != nil {
		return nil, fmt.Errorf("credential response encryption: %w", withCode(receiverTypes.ErrInvalidMetadata, err))
	}

	holderKeys := publicKeys(req.HolderKeys)
	issuerRequired := issuerRequiresKeyAttestation(config)
	withAttestation := issuerRequired || req.IncludeKeyAttestation || req.KeyAttestation != nil
	required := func(g *IssuanceGrant, nonceRejected bool) *KeyAttestationRequiredError {
		return &KeyAttestationRequiredError{
			Grant: g, CNonce: g.CNonce, HolderKeys: holderKeys, Audience: md.CredentialIssuer,
			IssuerRequired: issuerRequired, NonceRejected: nonceRejected,
		}
	}
	if withAttestation {
		if md.NonceEndpoint == nil && w.profile.IsHAIP() {
			return nil, fmt.Errorf("the credential configuration %q is requested with a key attestation: %w", grant.CredentialConfigurationID, ErrNonceEndpointRequired)
		}
		if req.KeyAttestation == nil && w.attestationSettings().Key == nil {
			return nil, required(grant, false)
		}
		// An attestation minted outside the wallet is bound to one c_nonce
		// (Appendix D.1); a stale one would only spend the issuer's nonce.
		if req.KeyAttestation != nil && grant.CNonce != "" {
			claims, err := jwsClaims(req.KeyAttestation.JWT)
			if err != nil {
				return nil, fmt.Errorf("key attestation is malformed: %w: %w", attestation.ErrKeyAttestationInvalid, err)
			}
			if nonce, _ := claims["nonce"].(string); nonce != grant.CNonce {
				return nil, required(grant, true)
			}
		}
	}

	identifier := ""
	if len(grant.CredentialIdentifiers) > 0 {
		identifier = grant.CredentialIdentifiers[0]
	}
	// lastNonce is the c_nonce of the last body built; an invalid_nonce retry
	// replaces it.
	lastNonce := grant.CNonce
	build := func(cNonce string) ([]byte, string, error) {
		lastNonce = cNonce
		keyAttestation := ""
		if withAttestation {
			if req.KeyAttestation != nil && cNonce != grant.CNonce {
				// The issuer answered invalid_nonce; the supplied attestation
				// cannot be re-signed here.
				return nil, "", ErrKeyAttestationNonceRejected
			}
			jwt, err := w.keyAttestationFor(ctx, req.KeyAttestation, attestation.KeyRequest{
				Keys: holderKeys, Nonce: cNonce, Audience: md.CredentialIssuer,
			}, signingAlgValues)
			if err != nil {
				return nil, "", err
			}
			keyAttestation = jwt
		}
		proofs := make([]string, 0, len(req.HolderKeys))
		for _, key := range req.HolderKeys {
			proof, err := jwtproof.KeyProof(ctx, key, jwtproof.KeyProofOptions{
				Audience:         md.CredentialIssuer,
				Nonce:            cNonce,
				KeyAttestation:   keyAttestation,
				SigningAlgValues: signingAlgValues,
			})
			if err != nil {
				return nil, "", err
			}
			proofs = append(proofs, proof)
		}
		payload := map[string]any{"proofs": map[string]any{"jwt": proofs}}
		// Section 8.2: credential_identifier replaces
		// credential_configuration_id once the token response named one.
		if identifier != "" {
			payload["credential_identifier"] = identifier
		} else {
			payload["credential_configuration_id"] = grant.CredentialConfigurationID
		}
		if encryption != nil {
			payload["credential_response_encryption"] = encryption
		}
		body, contentType, err := transport.EncodeCredentialRequest(payload, md)
		if err != nil {
			return nil, "", fmt.Errorf("failed to encode credential request: %w", err)
		}
		return body, contentType, nil
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	token := *grant.AccessToken
	endpoint := md.CredentialEndpoint
	raw, err := transport.RequestCredential(ctx, endpoint, token, grant.CNonce, build, md.NonceEndpoint,
		dpopProofFactory(ctx, dpopKey, http.MethodPost, endpoint.String(), token.Token))
	if err != nil {
		if errors.Is(err, ErrKeyAttestationNonceRejected) {
			refreshed := *grant
			refreshed.CNonce = lastNonce
			return nil, required(&refreshed, true)
		}
		return nil, fmt.Errorf("failed to receive credential: %w", err)
	}
	response, err := decodeCredentialResponse(transport, raw, decryptionKey, len(req.HolderKeys))
	if err != nil {
		return nil, err
	}
	if response.TransactionID != "" {
		if md.DeferredCredentialEndpoint == nil {
			return nil, invalidMetadata("deferred credential endpoint is missing on credential issuer")
		}
		return &IssuanceResult{
			CredentialResponse: response,
			Deferred: &DeferredIssuance{
				Version:                   IssuanceVersionFinal,
				CredentialIssuer:          md.CredentialIssuer,
				CredentialConfigurationID: grant.CredentialConfigurationID,
				TransactionID:             response.TransactionID,
				AccessToken:               grant.AccessToken,
				Interval:                  intervalDuration(response.Interval),
				HolderKeys:                holderKeys,
				ResponseDecryptionKey:     decryptionKey,
				DPoPKeyThumbprint:         grant.DPoPKeyThumbprint,
				cache:                     w.newIssuanceMetadataCache(discovery),
			},
		}, nil
	}
	return w.acceptCredentialResponse(ctx, md, grant.CredentialConfigurationID, grant.AccessToken, grant.DPoPKeyThumbprint, response, holderKeys)
}

// acceptCredentialResponse verifies and stores the credentials of response.
// On refusal the result carries the notification for credential_failure.
func (w *Wallet) acceptCredentialResponse(
	ctx context.Context,
	md *receiverTypes.CredentialIssuerMetadata,
	configurationID string,
	token *receiverTypes.CredentialIssuanceAccessToken,
	dpopThumbprint string,
	response *receiverTypes.CredentialResponse,
	holderKeys []jose.JSONWebKey,
) (*IssuanceResult, error) {
	result := &IssuanceResult{CredentialResponse: response}
	if response.NotificationID != "" {
		result.Notification = &IssuanceNotification{
			Version:           IssuanceVersionFinal,
			CredentialIssuer:  md.CredentialIssuer,
			NotificationID:    response.NotificationID,
			AccessToken:       token,
			DPoPKeyThumbprint: dpopThumbprint,
		}
	}
	saved, err := w.storeCredentialResponse(ctx, response, md, configurationID, holderKeys)
	if err != nil {
		return result, err
	}
	result.Credentials = saved
	return result, nil
}

// checkGrant checks that grant is a complete state of version.
func checkGrant(grant *IssuanceGrant, version IssuanceVersion) error {
	if grant == nil {
		return invalidArgument("grant is required")
	}
	if grant.Version != version {
		return fmt.Errorf("grant has version %q: %w", grant.Version, ErrIssuanceVersionMismatch)
	}
	if grant.CredentialIssuer == "" || grant.CredentialConfigurationID == "" || grant.AuthorizationServer == "" {
		return fmt.Errorf("grant does not name its credential issuer, configuration and authorization server: %w", ErrIssuanceStateMismatch)
	}
	return nil
}

// checkHolderKeys requires at least one holder key and no nil entry.
func checkHolderKeys(keys []IKeyEntry) error {
	if len(keys) == 0 {
		return invalidArgument("at least one holder key is required")
	}
	for index, key := range keys {
		if key == nil {
			return invalidArgument("holder key %d is nil", index)
		}
	}
	return nil
}

// intervalDuration converts a Section 9 interval in seconds.
func intervalDuration(seconds int) time.Duration {
	if seconds <= 0 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

// proofSigningAlgValues reads proof_signing_alg_values_supported of the jwt
// proof type (Section 12.2.4); empty imposes no constraint.
func proofSigningAlgValues(config receiverTypes.CredentialConfiguration) []jose.SignatureAlgorithm {
	if config.ProofTypesSupported == nil {
		return nil
	}
	jwtProof, ok := (*config.ProofTypesSupported)["jwt"]
	if !ok {
		return nil
	}
	return jwtProof.ProofSigningAlgValuesSupported
}

// requireJWTProofType refuses a configuration whose proof_types_supported
// lacks jwt; one without proof_types_supported requires no proof.
func requireJWTProofType(configurationID string, config receiverTypes.CredentialConfiguration) error {
	if config.ProofTypesSupported == nil {
		return nil
	}
	if _, ok := (*config.ProofTypesSupported)["jwt"]; ok {
		return nil
	}
	types := make([]string, 0, len(*config.ProofTypesSupported))
	for name := range *config.ProofTypesSupported {
		types = append(types, name)
	}
	slices.Sort(types)
	return fmt.Errorf("credential configuration %q lists proof types %v: %w", configurationID, types, ErrProofTypeUnsupported)
}

// decodeCredentialResponse decodes a (Deferred) Credential Response with the
// transport and applies the Section 8.3 shape rules: at most maxCredentials
// credentials, one per key proof.
func decodeCredentialResponse(transport receiverTypes.CredentialTransport, raw *receiverTypes.CredentialEndpointHTTPResponse, key *jose.JSONWebKey, maxCredentials int) (*receiverTypes.CredentialResponse, error) {
	var decryptionKey any
	if key != nil {
		decryptionKey = key.Key
	}
	response, err := transport.DecodeCredentialResponse(raw.Body, raw.ContentType, decryptionKey, false)
	if err != nil {
		return nil, fmt.Errorf("failed to decode credential response: %w", err)
	}
	if err := validateCredentialResponse(response, maxCredentials); err != nil {
		return nil, fmt.Errorf("failed to decode credential response: %w", err)
	}
	return response, nil
}

// validateCredentialResponse checks the OpenID4VCI 1.0 Section 8.3 shape: a
// credentials array of objects with a credential member, or a transaction_id,
// never both; a notification_id or interval only with the matching shape.
func validateCredentialResponse(r *receiverTypes.CredentialResponse, maxCredentials int) error {
	if r == nil {
		return fmt.Errorf("%w: credential response is nil", ErrCredentialResponseShape)
	}
	if r.Credential != nil {
		return fmt.Errorf("%w: credential response used the removed singular credential member; OpenID4VCI 1.0 Section 8.3 requires the credentials array", ErrCredentialResponseShape)
	}
	count := len(r.Credentials)
	switch {
	case r.TransactionID != "" && count > 0:
		return fmt.Errorf("%w: credential response contained both transaction_id and credential content", ErrCredentialResponseShape)
	case r.TransactionID == "" && count == 0:
		return fmt.Errorf("%w: credential response contained neither credentials nor a transaction_id", ErrCredentialResponseShape)
	case r.NotificationID != "" && count == 0:
		return fmt.Errorf("%w: credential response carried a notification_id without credentials", ErrCredentialResponseShape)
	case r.Interval != 0 && count > 0:
		return fmt.Errorf("%w: credential response carried an interval together with credentials", ErrCredentialResponseShape)
	case count > max(maxCredentials, 1):
		return fmt.Errorf("%w: credential response contained %d credentials, but the request asked for %d", ErrCredentialResponseMultipleCredentials, count, max(maxCredentials, 1))
	}
	for index, value := range r.Credentials {
		object, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("%w: credentials[%d] is %T, not an object", ErrCredentialResponseShape, index, value)
		}
		if _, ok := object["credential"]; !ok {
			return fmt.Errorf("%w: credentials[%d] has no credential member", ErrCredentialResponseShape, index)
		}
	}
	return nil
}

// storeCredentialResponse verifies each credential against the holder key its
// cnf names and saves them all, or nothing when one fails acceptance.
func (w *Wallet) storeCredentialResponse(ctx context.Context, response *receiverTypes.CredentialResponse, md *receiverTypes.CredentialIssuerMetadata, configurationID string, holderKeys []jose.JSONWebKey) ([]*SavedCredential, error) {
	mimeType := mimeTypeForCredentialConfiguration(md, configurationID)
	flavor, err := (&credstoreTypes.CredentialEntry{MimeType: mimeType}).SerializationFlavor()
	if err != nil {
		return nil, fmt.Errorf("unsupported credential serialization flavor: %w", err)
	}
	bindingRequired := credentialBindingRequired(md, configurationID)
	saved := make([]*SavedCredential, 0, len(response.Credentials))
	usedKeys := make([]bool, len(holderKeys))
	for _, value := range response.Credentials {
		raw, err := rawCredentialBytes(value)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrCredentialResponseShape, err)
		}
		// Section 8.3 does not order the credentials like the proofs, so each
		// one is matched to the holder key its cnf names.
		holderKey, err := matchBatchHolderKey(raw, flavor, holderKeys, usedKeys, bindingRequired)
		if err != nil {
			return nil, err
		}
		parsed, verification, err := w.verifyCredentialForAcceptanceContext(ctx, raw, flavor, holderKey, true)
		if err != nil {
			return nil, fmt.Errorf("failed to verify credential: %w", err)
		}
		entry := credstoreTypes.CredentialEntry{Id: uuid.New().String(), ReceivedAt: time.Now(), Raw: raw, MimeType: mimeType}
		saved = append(saved, &SavedCredential{Credential: parsed, Entry: &entry, Verification: verification})
	}
	return saved, w.saveCredentials(saved)
}

// saveCredentials writes saved to the credential store; a storeless wallet
// leaves persisting them to the caller.
func (w *Wallet) saveCredentials(saved []*SavedCredential) error {
	if w.credStore == nil {
		return nil
	}
	for _, credential := range saved {
		if err := w.credStore.SaveCredentialEntry(*credential.Entry, credstoreTypes.SupportedCredStoreTypes(0)); err != nil {
			return fmt.Errorf("failed to save credential entry: %w", err)
		}
	}
	return nil
}

// credentialBindingRequired reports whether the configuration lists
// cryptographic_binding_methods_supported (Section 12.2.4).
func credentialBindingRequired(md *receiverTypes.CredentialIssuerMetadata, configurationID string) bool {
	if md == nil {
		return false
	}
	config, ok := md.CredentialConfigurationSupported[configurationID]
	return ok && configurationRequiresBinding(config)
}

// configurationRequiresBinding reports whether config lists
// cryptographic_binding_methods_supported.
func configurationRequiresBinding(config receiverTypes.CredentialConfiguration) bool {
	return config.CryptographicBindingMethodsSupported != nil && len(*config.CryptographicBindingMethodsSupported) > 0
}

// matchBatchHolderKey selects the holder key whose RFC 7638 thumbprint equals
// the credential's cnf.jwk, each key at most once. A credential without cnf is
// refused when binding is required and otherwise takes the first unused key.
func matchBatchHolderKey(raw []byte, flavor credential.SupportedSerializationFlavor, holderKeys []jose.JSONWebKey, usedKeys []bool, bindingRequired bool) (*jose.JSONWebKey, error) {
	if len(holderKeys) == 0 && !bindingRequired {
		return nil, nil
	}
	claimed, err := credentialConfirmationKey(raw, flavor)
	if err != nil {
		return nil, err
	}
	if claimed == nil && bindingRequired {
		return nil, fmt.Errorf("the credential configuration requires cryptographic binding: %w", acceptance.ErrHolderBindingMissing)
	}
	if len(holderKeys) == 0 {
		return nil, nil
	}
	if claimed == nil {
		for index := range holderKeys {
			if !usedKeys[index] {
				usedKeys[index] = true
				publicKey := holderKeys[index].Public()
				return &publicKey, nil
			}
		}
		return nil, fmt.Errorf("%w: more credentials than holder keys", ErrCredentialResponseMultipleCredentials)
	}
	claimedThumbprint, err := claimed.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("cnf jwk thumbprint failed: %w: %w", acceptance.ErrHolderBindingMismatch, err)
	}
	for index := range holderKeys {
		publicKey := holderKeys[index].Public()
		thumbprint, err := publicKey.Thumbprint(crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("holder key thumbprint failed: %w", err)
		}
		if !bytes.Equal(thumbprint, claimedThumbprint) {
			continue
		}
		if usedKeys[index] {
			return nil, fmt.Errorf("credential response bound two credentials to the same holder key: %w", acceptance.ErrHolderBindingMismatch)
		}
		usedKeys[index] = true
		return &publicKey, nil
	}
	return nil, fmt.Errorf("credential is bound to a holder key that was not part of the request: %w", acceptance.ErrHolderBindingMismatch)
}

// credentialConfirmationKey reads cnf.jwk from the issuer-signed JWT, or the
// subject DID key of a W3C VC, without verifying it; nil when there is none.
func credentialConfirmationKey(raw []byte, flavor credential.SupportedSerializationFlavor) (*jose.JSONWebKey, error) {
	if flavor == credential.LdpVc {
		var document map[string]any
		if err := json.Unmarshal(raw, &document); err != nil {
			return nil, fmt.Errorf("data integrity credential: %w: %w", acceptance.ErrCredentialParse, err)
		}
		return subjectDIDKey(map[string]any{"vc": document})
	}
	token := string(raw)
	if flavor == credential.SDJwtVC {
		token, _, _ = strings.Cut(token, "~")
	}
	claims, err := jwsClaims(token)
	if err != nil {
		return nil, fmt.Errorf("issuer JWT: %w: %w", acceptance.ErrCredentialParse, err)
	}
	cnf, _ := claims["cnf"].(map[string]any)
	if cnf == nil || cnf["jwk"] == nil {
		if flavor == credential.JwtVc {
			return subjectDIDKey(claims)
		}
		return nil, nil
	}
	encoded, err := json.Marshal(cnf["jwk"])
	if err != nil {
		return nil, fmt.Errorf("cnf jwk is invalid: %w: %w", acceptance.ErrCredentialParse, err)
	}
	var key jose.JSONWebKey
	if err := key.UnmarshalJSON(encoded); err != nil {
		return nil, fmt.Errorf("cnf jwk is invalid: %w: %w", acceptance.ErrCredentialParse, err)
	}
	return &key, nil
}

// subjectDIDKey returns the key a W3C VC is bound to through its subject DID
// (the JWT sub, or vc.credentialSubject.id), for the did:key and did:jwk
// methods, which resolve without network access. Any other subject yields no
// key, so a configuration that requires binding refuses the credential.
func subjectDIDKey(claims map[string]any) (*jose.JSONWebKey, error) {
	subject, _ := claims["sub"].(string)
	if subject == "" {
		if vc, ok := claims["vc"].(map[string]any); ok {
			if credentialSubject, ok := vc["credentialSubject"].(map[string]any); ok {
				subject, _ = credentialSubject["id"].(string)
			}
		}
	}
	if !strings.HasPrefix(subject, "did:key:") && !strings.HasPrefix(subject, "did:jwk:") {
		return nil, nil
	}
	profile, err := did.NewDIDPlugin().Resolve(subject)
	if err != nil {
		return nil, fmt.Errorf("credential subject DID cannot be resolved: %w: %w", acceptance.ErrHolderBindingMismatch, err)
	}
	if profile == nil || profile.Keys == nil || len(profile.Keys.Keys) != 1 {
		return nil, fmt.Errorf("credential subject DID must name exactly one key: %w", acceptance.ErrHolderBindingMismatch)
	}
	key := profile.Keys.Keys[0]
	return &key, nil
}

// rawCredentialBytes unwraps a credentials element (Section 8.3: an object
// whose credential member is a string or a JSON object).
func rawCredentialBytes(value any) ([]byte, error) {
	switch credentialValue := value.(type) {
	case string:
		return []byte(credentialValue), nil
	case []byte:
		return credentialValue, nil
	case map[string]any:
		if inner, ok := credentialValue["credential"]; ok && len(credentialValue) == 1 {
			return rawCredentialBytes(inner)
		}
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credential value: %w", err)
	}
	return raw, nil
}

// mimeTypeForCredentialConfiguration maps the configuration's format to the
// stored MIME type.
func mimeTypeForCredentialConfiguration(md *receiverTypes.CredentialIssuerMetadata, configurationID string) string {
	if md != nil {
		if config, ok := md.CredentialConfigurationSupported[configurationID]; ok {
			switch config.Format {
			case "dc+sd-jwt", "vc+sd-jwt":
				return string(credential.SDJwtVC)
			case "jwt_vc_json", "jwt_vc", "vc+jwt":
				return string(credential.JwtVc)
			case "ldp_vc":
				return string(credential.LdpVc)
			}
		}
	}
	return string(credential.JwtVc)
}
