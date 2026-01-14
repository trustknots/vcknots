// Package credential defines the structures and types used for handling credentials in the wallet system.
// It includes definitions for credential entries, presentations, subjects, and related metadata.
package credential

import (
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
)

type SupportedSerializationFlavor string // mime type

const (
	JwtVc      SupportedSerializationFlavor = "application/vc+jwt"
	SDJwtVC    SupportedSerializationFlavor = "application/dc+sd-jwt"
	MockFormat SupportedSerializationFlavor = "plain/mock" // For testing
)

// for OID4VP presentation submission. (vc format, vp format, err)
func (sf *SupportedSerializationFlavor) OID4VPFormatIdentifier() (string, string, error) {
	switch *sf {
	case JwtVc:
		return "jwt_vc_json", "jwt_vp_json", nil
	case SDJwtVC:
		return "dc+sd-jwt", "dc+sd-jwt", nil
	case MockFormat:
		return "mock_vc", "mock_vp", nil
	default:
		return "", "", fmt.Errorf("unknown serialization flavor")
	}
}

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
}

type CredentialPresentation struct {
	ID          string
	Types       []string
	Credentials [][]byte
	Holder      string
	Proof       *CredentialProof
	Nonce       *string
}

type CredentialValidPeriod struct {
	From *time.Time
	To   *time.Time
}

type CredentialClaim map[string]any

type CredentialProof struct {
	Algorithm jose.SignatureAlgorithm `json:"alg"`
	Signature []byte                  `json:"signature"`
	Payload   []byte                  `json:"payload"`
}
