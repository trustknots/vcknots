// Package credential defines the structures and types used for handling credentials in the wallet system.
// It includes definitions for credential entries, presentations, subjects, and related metadata.
package credential

import (
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// SupportedSerializationFlavor names a credential serialization format by its
// media type.
type SupportedSerializationFlavor string // mime type

// Credential serialization formats.
const (
	// JwtVc is a W3C Verifiable Credential secured as a JWT.
	JwtVc SupportedSerializationFlavor = "application/vc+jwt"
	// SDJwtVC is an SD-JWT VC.
	SDJwtVC SupportedSerializationFlavor = "application/dc+sd-jwt"
	// LdpVc is a W3C Verifiable Credential secured with an embedded Data
	// Integrity proof, under the VC Data Model 2.0 media type (Section 6.3).
	LdpVc SupportedSerializationFlavor = "application/vc"
	// MockFormat is a plain-text format for mock and test plugins.
	MockFormat SupportedSerializationFlavor = "plain/mock" // For testing
)

// for OID4VP presentation submission. (vc format, vp format, err)
func (sf *SupportedSerializationFlavor) OID4VPFormatIdentifier() (string, string, error) {
	switch *sf {
	case JwtVc:
		return "jwt_vc_json", "jwt_vp_json", nil
	case SDJwtVC:
		return "dc+sd-jwt", "dc+sd-jwt", nil
	case LdpVc:
		// OpenID4VP Appendix B.1.3: ldp_vc credentials travel in an ldp_vp.
		return "ldp_vc", "ldp_vp", nil
	case MockFormat:
		return "mock_vc", "mock_vp", nil
	default:
		return "", "", fmt.Errorf("unknown serialization flavor")
	}
}

// Credential is the format-independent view of a decoded credential.
type Credential struct {
	ID          string
	Types       []string
	Name        string
	Description string
	Issuer      string
	Subject     string
	Claims      *CredentialClaim
	ValidPeriod *CredentialValidPeriod
	Proof       *CredentialProof
	SDJwt       *SDJwtCredentialMetadata
}

// CredentialPresentation is the format-independent view of a verifiable
// presentation of one or more serialized credentials.
type CredentialPresentation struct {
	ID          string
	Types       []string
	Credentials [][]byte
	Holder      string
	Proof       *CredentialProof
	Nonce       *string
}

// CredentialValidPeriod is the validity window of a credential; a nil bound is
// unbounded.
type CredentialValidPeriod struct {
	From *time.Time
	To   *time.Time
}

// CredentialClaim holds the claims of a credential by name.
type CredentialClaim map[string]any

// CredentialProof is the signature of a credential or presentation: its
// algorithm, signature bytes and the signed payload.
type CredentialProof struct {
	Algorithm jose.SignatureAlgorithm `json:"alg"`
	Signature []byte                  `json:"signature"`
	Payload   []byte                  `json:"payload"`
}

// SDJwtCredentialMetadata carries the selective disclosure data of an SD-JWT:
// the _sd digests, the _sd_alg hash algorithm and the parsed disclosures.
type SDJwtCredentialMetadata struct {
	SD          []string
	SDAlg       string
	Disclosures []SDJwtDisclosure
}

// SDJwtDisclosure is one parsed SD-JWT disclosure. Name is empty for an array
// element disclosure; EncodedValue is the disclosure as received.
type SDJwtDisclosure struct {
	Name           string
	Value          any
	Digest         string
	EncodedValue   string
	IsArrayElement bool
}
