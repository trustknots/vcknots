// Package credential defines the structures and types used for handling credentials in the wallet system.
// It includes definitions for credential entries, presentations, subjects, and related metadata.
package credential

import (
	"time"

	"github.com/go-jose/go-jose/v4"
)

type SupportedSerializationFlavor string // mime type

const (
	JwtVc      SupportedSerializationFlavor = "application/vc+jwt"
	SDJwtVC    SupportedSerializationFlavor = "application/dc+sd-jwt"
	MockFormat SupportedSerializationFlavor = "plain/mock" // For testing
)

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
