// Package ldpvc serializes W3C Verifiable Credentials secured with an embedded
// Data Integrity proof: the OpenID4VP ldp_vc credential format and the ldp_vp
// presentation format (OpenID4VP Appendix B.1.3).
//
// A presentation is a W3C Verifiable Presentation that embeds the credentials
// as JSON objects and carries an eddsa-rdfc-2022 DataIntegrityProof with
// proofPurpose "authentication". Its challenge is the request nonce and its
// domain the Verifier's client_id, which is how OpenID4VP Appendix B.1.3.1
// binds an ldp_vp to one Authorization Request. The holder is the did:key of
// the Ed25519 presentation key, and the proof's verificationMethod is that
// DID's only key.
//
// JSON-LD contexts are never fetched: the presentation's @context and every
// context its credentials name must be pinned in the options (see package
// credential/dataintegrity).
package ldpvc

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/credential/dataintegrity"
	"github.com/trustknots/vcknots/wallet/idprof/plugins/did"
	"github.com/trustknots/vcknots/wallet/keystore"
	"github.com/trustknots/vcknots/wallet/serializer/types"
)

// verifiablePresentationType is the base type every presentation carries (VC
// Data Model Section 4.13).
const verifiablePresentationType = "VerifiablePresentation"

// LdpVcSerializer implements types.Serializer for credential.LdpVc.
type LdpVcSerializer struct{}

// NewLdpVcSerializer creates the Data Integrity serializer.
func NewLdpVcSerializer() (*LdpVcSerializer, error) {
	return &LdpVcSerializer{}, nil
}

// LdpVcPresentationOptions configures one ldp_vp. Context and Contexts have no
// usable default: which vocabulary a presentation speaks, and which context
// documents a wallet trusts to define it, are the integrator's decisions.
type LdpVcPresentationOptions struct {
	// Context is the presentation's @context: a URL string or a JSON array of
	// URLs and inline context objects.
	Context any
	// Contexts pins every remote context the presentation and the credentials
	// it embeds name.
	Contexts dataintegrity.PinnedContexts
	// Challenge is the proof challenge; OpenID4VP sets it to the request nonce.
	Challenge string
	// Domain is the proof domain; OpenID4VP sets it to the client_id.
	Domain string
	// Created is the proof creation time. The zero value means now.
	Created time.Time
}

// IsSerializePresentationOptions implements types.SerializePresentationOptions.
func (o *LdpVcPresentationOptions) IsSerializePresentationOptions() {}

// SetAudience sets the proof domain.
func (o *LdpVcPresentationOptions) SetAudience(audience string) {
	if o != nil {
		o.Domain = audience
	}
}

// SetNonce sets the proof challenge.
func (o *LdpVcPresentationOptions) SetNonce(nonce string) {
	if o != nil {
		o.Challenge = nonce
	}
}

// SerializeCredential is not supported: a Data Integrity credential is secured
// by its issuer, and the wallet only ever stores the issued document.
func (s *LdpVcSerializer) SerializeCredential(flavor credential.SupportedSerializationFlavor, cred *credential.Credential) ([]byte, error) {
	if flavor != credential.LdpVc {
		return nil, types.NewFormatError(flavor, types.ErrUnsupportedFormat, "expected Data Integrity VC format")
	}
	return nil, types.NewFormatError(flavor, errors.New("not implemented"), "SerializeCredential is not supported for Data Integrity credentials")
}

// DeserializeCredential reads the descriptive members of a Data Integrity
// credential. It does not verify the issuer's proof.
func (s *LdpVcSerializer) DeserializeCredential(flavor credential.SupportedSerializationFlavor, data []byte) (*credential.Credential, error) {
	if flavor != credential.LdpVc {
		return nil, types.NewFormatError(flavor, types.ErrUnsupportedFormat, "expected Data Integrity VC format")
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil || document == nil {
		return nil, types.NewInvalidCredentialError("a Data Integrity credential must be a JSON object", err)
	}
	credentialTypes, err := stringOrStrings(document["type"])
	if err != nil {
		return nil, types.NewInvalidCredentialError("type must be a string or an array of strings", err)
	}
	issuer, err := issuerID(document["issuer"])
	if err != nil {
		return nil, types.NewInvalidCredentialError("issuer must be a URL or an object with an id", err)
	}
	result := &credential.Credential{Types: credentialTypes, Issuer: issuer}
	if id, ok := document["id"].(string); ok {
		result.ID = id
	}
	if name, ok := document["name"].(string); ok {
		result.Name = name
	}
	if description, ok := document["description"].(string); ok {
		result.Description = description
	}
	if subject, ok := document["credentialSubject"].(map[string]any); ok {
		claims := credential.CredentialClaim{}
		for name, value := range subject {
			if name == "id" {
				if id, ok := value.(string); ok {
					result.Subject = id
				}
				continue
			}
			claims[name] = value
		}
		result.Claims = &claims
	}
	validPeriod, err := validityPeriod(document)
	if err != nil {
		return nil, types.NewInvalidCredentialError("invalid validity period", err)
	}
	result.ValidPeriod = validPeriod
	return result, nil
}

// SerializePresentation builds the Verifiable Presentation, embeds the
// credentials and signs it with an eddsa-rdfc-2022 authentication proof.
//
// key must hold an Ed25519 key; its Sign must return the RFC 8032 signature of
// the bytes it is given (Ed25519 hashes internally, so no digest is applied
// first).
func (s *LdpVcSerializer) SerializePresentation(flavor credential.SupportedSerializationFlavor, presentation *credential.CredentialPresentation, key keystore.KeyEntry, options types.SerializePresentationOptions) ([]byte, *credential.CredentialPresentation, error) {
	if flavor != credential.LdpVc {
		return nil, nil, types.NewFormatError(flavor, types.ErrUnsupportedFormat, "expected Data Integrity VC format")
	}
	opts, ok := options.(*LdpVcPresentationOptions)
	if !ok || opts == nil {
		return nil, nil, fmt.Errorf("%w: Data Integrity presentation options are required", types.ErrInvalidPresentation)
	}
	if opts.Context == nil || len(opts.Contexts) == 0 {
		return nil, nil, fmt.Errorf("%w: the presentation @context and the pinned contexts are required", types.ErrInvalidPresentation)
	}
	if len(presentation.Credentials) == 0 {
		return nil, nil, fmt.Errorf("%w: a Data Integrity presentation requires at least one credential", types.ErrInvalidPresentation)
	}

	holder, verificationMethod, err := holderVerificationMethod(key)
	if err != nil {
		return nil, nil, err
	}
	if presentation.Holder != "" && presentation.Holder != holder {
		return nil, nil, fmt.Errorf("%w: holder %s is not the DID of the presentation key", types.ErrInvalidPresentation, presentation.Holder)
	}

	embedded := make([]any, 0, len(presentation.Credentials))
	for index, raw := range presentation.Credentials {
		var document map[string]any
		if err := json.Unmarshal(raw, &document); err != nil || document == nil {
			return nil, nil, types.NewInvalidCredentialError(fmt.Sprintf("credential %d is not a JSON object", index), err)
		}
		embedded = append(embedded, document)
	}

	presentationTypes := presentation.Types
	if len(presentationTypes) == 0 {
		presentationTypes = []string{verifiablePresentationType}
	}
	typeValues := make([]any, len(presentationTypes))
	for index, value := range presentationTypes {
		typeValues[index] = value
	}
	document := map[string]any{
		"@context":             opts.Context,
		"type":                 typeValues,
		"holder":               holder,
		"verifiableCredential": embedded,
	}
	if presentation.ID != "" {
		document["id"] = presentation.ID
	}

	challenge := opts.Challenge
	if challenge == "" && presentation.Nonce != nil {
		challenge = *presentation.Nonce
	}
	created := opts.Created
	if created.IsZero() {
		created = time.Now()
	}

	var signature, hashData []byte
	signed, err := dataintegrity.SignEddsaRdfc2022(document, dataintegrity.ProofOptions{
		VerificationMethod: verificationMethod,
		ProofPurpose:       dataintegrity.ProofPurposeAuthentication,
		Created:            created,
		Challenge:          challenge,
		Domain:             opts.Domain,
	}, opts.Contexts, func(data []byte) ([]byte, error) {
		hashData = data
		signed, err := key.Sign(data)
		signature = signed
		return signed, err
	})
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", types.ErrSigningFailed, err)
	}
	serialized, err := json.Marshal(signed)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", types.ErrInvalidPresentation, err)
	}

	return serialized, &credential.CredentialPresentation{
		ID:          presentation.ID,
		Types:       presentationTypes,
		Credentials: presentation.Credentials,
		Holder:      holder,
		Nonce:       presentation.Nonce,
		Proof: &credential.CredentialProof{
			Algorithm: jose.EdDSA,
			Signature: signature,
			Payload:   hashData,
		},
	}, nil
}

// DeserializePresentation reads an ldp_vp's members. It does not verify the
// proof.
func (s *LdpVcSerializer) DeserializePresentation(flavor credential.SupportedSerializationFlavor, data []byte) (*credential.CredentialPresentation, error) {
	if flavor != credential.LdpVc {
		return nil, types.NewFormatError(flavor, types.ErrUnsupportedFormat, "expected Data Integrity VC format")
	}
	var document struct {
		ID                   string            `json:"id"`
		Type                 any               `json:"type"`
		Holder               any               `json:"holder"`
		VerifiableCredential []json.RawMessage `json:"verifiableCredential"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("%w: %w", types.ErrInvalidPresentation, err)
	}
	presentationTypes, err := stringOrStrings(document.Type)
	if err != nil {
		return nil, fmt.Errorf("%w: type: %w", types.ErrInvalidPresentation, err)
	}
	holder, err := issuerID(document.Holder)
	if err != nil && document.Holder != nil {
		return nil, fmt.Errorf("%w: holder: %w", types.ErrInvalidPresentation, err)
	}
	credentials := make([][]byte, len(document.VerifiableCredential))
	for index, raw := range document.VerifiableCredential {
		credentials[index] = raw
	}
	return &credential.CredentialPresentation{
		ID:          document.ID,
		Types:       presentationTypes,
		Credentials: credentials,
		Holder:      holder,
	}, nil
}

// GetDefaultOption returns empty options. They cannot serialize a presentation
// until the caller supplies the @context and the pinned contexts.
func (s *LdpVcSerializer) GetDefaultOption(flavor credential.SupportedSerializationFlavor) (types.SerializePresentationOptions, error) {
	if flavor != credential.LdpVc {
		return nil, types.NewFormatError(flavor, types.ErrUnsupportedFormat, "expected Data Integrity VC format")
	}
	return &LdpVcPresentationOptions{}, nil
}

// holderVerificationMethod derives the holder did:key and its only
// verification method, "did:key:<fp>#<fp>", from an Ed25519 presentation key.
func holderVerificationMethod(key keystore.KeyEntry) (string, string, error) {
	publicJWK := key.PublicKey()
	if _, ok := publicJWK.Key.(ed25519.PublicKey); !ok {
		return "", "", fmt.Errorf("%w: a Data Integrity eddsa-rdfc-2022 presentation requires an Ed25519 key", types.ErrUnsupportedAlgorithm)
	}
	profile, err := did.NewDIDKeyProfile(&did.DIDKeyProfileCreateOptions{
		DIDProfileCreateOptions: did.DIDProfileCreateOptions{Method: "key"},
		PublicKey:               &publicJWK,
	})
	if err != nil {
		return "", "", fmt.Errorf("%w: %w", types.ErrUnsupportedAlgorithm, err)
	}
	fingerprint := strings.TrimPrefix(profile.ID, "did:key:")
	return profile.ID, profile.ID + "#" + fingerprint, nil
}

func stringOrStrings(value any) ([]string, error) {
	switch typed := value.(type) {
	case string:
		return []string{typed}, nil
	case []any:
		values := make([]string, len(typed))
		for index, item := range typed {
			text, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("entry %d is not a string", index)
			}
			values[index] = text
		}
		return values, nil
	default:
		return nil, fmt.Errorf("unexpected %T", value)
	}
}

func issuerID(value any) (string, error) {
	switch typed := value.(type) {
	case string:
		return typed, nil
	case map[string]any:
		if id, ok := typed["id"].(string); ok {
			return id, nil
		}
	}
	return "", fmt.Errorf("unexpected %T", value)
}

// validityPeriod reads validFrom/validUntil (VC Data Model 2.0) or, for a 1.1
// credential, issuanceDate/expirationDate.
func validityPeriod(document map[string]any) (*credential.CredentialValidPeriod, error) {
	from, err := optionalDateTime(document, "validFrom", "issuanceDate")
	if err != nil {
		return nil, err
	}
	to, err := optionalDateTime(document, "validUntil", "expirationDate")
	if err != nil {
		return nil, err
	}
	if from == nil && to == nil {
		return nil, nil
	}
	return &credential.CredentialValidPeriod{From: from, To: to}, nil
}

func optionalDateTime(document map[string]any, names ...string) (*time.Time, error) {
	for _, name := range names {
		text, ok := document[name].(string)
		if !ok {
			continue
		}
		instant, err := time.Parse(time.RFC3339, text)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		return &instant, nil
	}
	return nil, nil
}
