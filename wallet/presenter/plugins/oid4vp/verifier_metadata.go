package oid4vp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/trustknots/vcknots/wallet/common"
)

// metadataContract names the client_metadata members one wire contract acts
// on and the members of the other version it never reads.
type metadataContract struct {
	// used are decoded strictly: a member of the wrong type refuses the
	// request, because the Wallet acts on it.
	used []string
	// foreign are the other version's members, dropped unread.
	foreign []string
}

var (
	// finalMetadata: OpenID4VP 1.0 §5.1 names jwks,
	// encrypted_response_enc_values_supported and vp_formats_supported, and
	// "Other metadata parameters MUST be ignored". vp_formats is the Draft 24
	// member; a 1.0 request is judged by vp_formats_supported alone.
	finalMetadata = metadataContract{
		used:    []string{"jwks", "encrypted_response_enc_values_supported", "vp_formats_supported"},
		foreign: []string{"vp_formats"},
	}
	// draft24Metadata: Draft 24 §5.1 names jwks, vp_formats and the JARM
	// members; vp_formats_supported and encrypted_response_enc_values_supported
	// are OpenID4VP 1.0 members.
	draft24Metadata = metadataContract{
		used: []string{"jwks", "vp_formats", "authorization_signed_response_alg",
			"authorization_encrypted_response_alg", "authorization_encrypted_response_enc"},
		foreign: []string{"vp_formats_supported", "encrypted_response_enc_values_supported"},
	}
)

// parseClientMetadataParam decodes the client_metadata parameter, which
// arrives as a JSON object (Request Object claim) or a JSON string (query
// parameter), under contract.
func parseClientMetadataParam(cm any, requireKeyIDs bool, contract metadataContract) (*VerifierMetadata, error) {
	var rawMetadata []byte
	switch value := cm.(type) {
	case map[string]any:
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal client_metadata: %w", err)
		}
		rawMetadata = encoded
	case string:
		rawMetadata = []byte(value)
	default:
		return nil, fmt.Errorf("client_metadata must be a string or map")
	}
	clientMeta, err := decodeVerifierMetadata(rawMetadata, contract)
	if err != nil {
		return nil, fmt.Errorf("invalid client_metadata: %w", err)
	}
	if requireKeyIDs {
		if err := validateClientMetadataJWKKeyIDs(rawMetadata); err != nil {
			return nil, newAuthorizationRequestError(InvalidRequestError, "%w", err)
		}
	}
	return clientMeta, nil
}

// decodeVerifierMetadata decodes Verifier metadata under contract. A member
// the contract uses must decode; any other member is kept only when it has
// the type VerifierMetadata models, and dropped otherwise, because the Wallet
// ignores it (OpenID4VP 1.0 §5.1: "Other metadata parameters MUST be
// ignored") and must not refuse a request over it. The other
// version's members are dropped unread.
func decodeVerifierMetadata(raw []byte, contract metadataContract) (*VerifierMetadata, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return nil, err
	}
	if members == nil {
		return nil, fmt.Errorf("client_metadata must be a JSON object")
	}
	kept := make(map[string]json.RawMessage, len(members))
	for name, value := range members {
		switch {
		case slices.Contains(contract.foreign, name):
		case slices.Contains(contract.used, name):
			kept[name] = value
		default:
			probe, err := json.Marshal(map[string]json.RawMessage{name: value})
			if err == nil && json.Unmarshal(probe, &VerifierMetadata{}) == nil {
				kept[name] = value
			}
		}
	}
	encoded, err := json.Marshal(kept)
	if err != nil {
		return nil, err
	}
	var metadata VerifierMetadata
	if err := json.Unmarshal(encoded, &metadata); err != nil {
		return nil, err
	}
	return &metadata, nil
}

// ErrVPFormatAlgUnsupported reports a presentation whose signing algorithm
// the Verifier's metadata does not list for its Credential Format: the
// Issuer-signed JWT or the Key Binding JWT of an SD-JWT VC outside
// sd-jwt_alg_values or kb-jwt_alg_values (OpenID4VP 1.0 Appendix B.3.4,
// Draft 24 Appendix B.4.2: "If present, the alg JOSE header ... MUST match one
// of the array values"). Nothing is sent.
var ErrVPFormatAlgUnsupported = common.NewCodedError("vp_format_alg_unsupported", "the Verifier's metadata does not accept the algorithm of the presentation")

// sdJWTFormatIdentifiers are the Credential Format Identifiers of an SD-JWT
// VC in Verifier metadata: dc+sd-jwt (OpenID4VP 1.0, Draft 24 §B.4) and the
// earlier vc+sd-jwt.
var sdJWTFormatIdentifiers = []string{"dc+sd-jwt", "vc+sd-jwt"}

// CheckSDJWTPresentationAlgorithms checks the Issuer-signed JWT and the Key
// Binding JWT of an SD-JWT VC presentation against the sd-jwt_alg_values and
// kb-jwt_alg_values the Verifier's metadata lists for the SD-JWT VC format:
// vp_formats_supported on an OpenID4VP 1.0 request, vp_formats on a Draft 24
// one. A list the Verifier omits accepts every algorithm, as does metadata
// that names no SD-JWT VC format.
func (m *VerifierMetadata) CheckSDJWTPresentationAlgorithms(presentation string) error {
	if m == nil {
		return nil
	}
	formats := m.VPFormatsSupported
	if len(formats) == 0 {
		formats = m.VPFormats
	}
	var constraints struct {
		SDJWTAlgValues []string `json:"sd-jwt_alg_values"`
		KBJWTAlgValues []string `json:"kb-jwt_alg_values"`
	}
	found := false
	for _, identifier := range sdJWTFormatIdentifiers {
		if raw, ok := formats[identifier]; ok {
			if err := json.Unmarshal(raw, &constraints); err != nil {
				return fmt.Errorf("%w: the %s entry of the Verifier's formats is not an object of algorithm lists", ErrVPFormatAlgUnsupported, identifier)
			}
			found = true
			break
		}
	}
	if !found {
		return nil
	}
	parts := strings.Split(presentation, "~")
	if err := requireJWSAlg(parts[0], constraints.SDJWTAlgValues, "Issuer-signed JWT", "sd-jwt_alg_values"); err != nil {
		return err
	}
	if keyBinding := parts[len(parts)-1]; len(parts) > 1 && keyBinding != "" {
		return requireJWSAlg(keyBinding, constraints.KBJWTAlgValues, "Key Binding JWT", "kb-jwt_alg_values")
	}
	return nil
}

// requireJWSAlg requires the alg header of the compact JWS token to be one of
// accepted, when accepted is not empty.
func requireJWSAlg(token string, accepted []string, what, member string) error {
	if len(accepted) == 0 {
		return nil
	}
	header, _, _ := strings.Cut(token, ".")
	decoded, err := base64.RawURLEncoding.DecodeString(header)
	var parsed struct {
		Alg string `json:"alg"`
	}
	if err != nil || json.Unmarshal(decoded, &parsed) != nil || parsed.Alg == "" {
		return fmt.Errorf("%w: the %s has no readable alg header", ErrVPFormatAlgUnsupported, what)
	}
	if !slices.Contains(accepted, parsed.Alg) {
		return fmt.Errorf("%w: the %s is signed with %s, and %s lists %v", ErrVPFormatAlgUnsupported, what, parsed.Alg, member, accepted)
	}
	return nil
}

// federationClient reports whether the request's Client Identifier is an
// OpenID Federation Entity Identifier, whose metadata comes from the Trust
// Chain alone.
func (b *requestBuilder) federationClient() bool {
	parsed, err := b.parseClientID(b.req.ClientID)
	return err == nil && parsed.prefix == OID4VPClientIDPrefixOIDFederation
}

// federationClient is requestBuilder.federationClient for Draft 24's https
// Client Identifier Scheme.
func (b *draft24RequestBuilder) federationClient() bool {
	parsed, err := b.parseClientID(b.req.ClientID)
	return err == nil && parsed.prefix == OID4VPClientIDPrefixOIDFederation
}
