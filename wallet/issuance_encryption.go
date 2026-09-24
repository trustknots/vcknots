package wallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"slices"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/internal/oid4vcijwe"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// CredentialEncryptionRule is the holder's rule for one of the two
// OpenID4VCI 1.0 credential encryptions.
type CredentialEncryptionRule int

const (
	// CredentialEncryptionFollowIssuer encrypts what the issuer metadata
	// advertises and obeys an issuer that requires it (Sections 8.1, 8.2).
	CredentialEncryptionFollowIssuer CredentialEncryptionRule = iota
	// CredentialEncryptionRequired refuses an issuer that does not offer the
	// encryption (ErrCredentialEncryptionUnavailable).
	CredentialEncryptionRequired
	// CredentialEncryptionDisabled asks for no encryption and refuses an
	// issuer that requires it (ErrCredentialEncryptionDisallowed).
	CredentialEncryptionDisabled
)

// CredentialEncryptionPolicy is the holder's policy for Credential Request
// (Section 8.1) and Credential Response (Section 8.2) encryption. An issuance
// that cannot honour it is refused at BeginIssuance or
// AuthorizePreAuthorizedIssuance; it is never downgraded. The response key
// travels only inside an encrypted request (Section 8.2), so requiring
// response encryption requires request encryption, and disabling either
// disables both.
type CredentialEncryptionPolicy struct {
	Request  CredentialEncryptionRule
	Response CredentialEncryptionRule
}

func (p CredentialEncryptionPolicy) disablesEncryption() bool {
	return p.Request == CredentialEncryptionDisabled || p.Response == CredentialEncryptionDisabled
}

// responseEncryptionKey returns a new ephemeral key the Credential Response is
// to be encrypted to, or nil when this issuance asks for no response
// encryption.
func (p CredentialEncryptionPolicy) responseEncryptionKey(md *receiverTypes.CredentialIssuerMetadata) (*jose.JSONWebKey, error) {
	if err := p.validate(md); err != nil {
		return nil, err
	}
	if p.disablesEncryption() || md == nil || md.CredentialResponseEncryption == nil || md.CredentialRequestEncryption == nil {
		return nil, nil
	}
	// validate refused a required encryption the wallet cannot read, so an
	// unusable one here is optional and is not asked for.
	if !responseEncryptionUsable(md.CredentialResponseEncryption) {
		return nil, nil
	}
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate a credential response encryption key: %w", err)
	}
	// The key names no alg: the receiver takes the first ECDH-ES algorithm of
	// alg_values_supported (Section 10).
	return &jose.JSONWebKey{Key: private, Use: "enc"}, nil
}

// responseEncryptionUsable reports whether the wallet's P-256 response key can
// be used with one of the issuer's alg_values_supported (any ECDH-ES
// algorithm the JWE allowlist admits, ECDH-ES itself when none is listed) and
// the wallet can decrypt one of its enc_values_supported.
func responseEncryptionUsable(encryption *receiverTypes.CredentialResponseEncryption) bool {
	algUsable := len(encryption.AlgValuesSupported) == 0
	for _, alg := range encryption.AlgValuesSupported {
		keyAlgorithm := jose.KeyAlgorithm(alg)
		if strings.HasPrefix(alg, string(jose.ECDH_ES)) && slices.Contains(oid4vcijwe.KeyAlgorithms(), keyAlgorithm) {
			algUsable = true
			break
		}
	}
	encUsable := false
	for _, enc := range encryption.EncValuesSupported {
		if slices.Contains(oid4vcijwe.ContentEncryptions(), jose.ContentEncryption(enc)) {
			encUsable = true
			break
		}
	}
	return algUsable && encUsable
}

// validate reports whether the issuer metadata can honour the policy.
func (p CredentialEncryptionPolicy) validate(md *receiverTypes.CredentialIssuerMetadata) error {
	if md == nil {
		return nil
	}
	responseEncryption := md.CredentialResponseEncryption
	requestEncryption := md.CredentialRequestEncryption
	issuerRequiresResponseEncryption := responseEncryption != nil &&
		responseEncryption.EncryptionRequired != nil && *responseEncryption.EncryptionRequired
	switch {
	case p.disablesEncryption() && issuerRequiresResponseEncryption:
		return fmt.Errorf("%w: the credential issuer requires credential response encryption", ErrCredentialEncryptionDisallowed)
	case issuerRequiresResponseEncryption && requestEncryption == nil:
		// Section 8.2: the request must be encrypted when it carries the
		// response key, so the issuer's own metadata leaves no valid request.
		return fmt.Errorf("%w: the credential issuer requires credential response encryption but advertises no credential_request_encryption", ErrCredentialEncryptionUnavailable)
	case p.Request == CredentialEncryptionDisabled && requestEncryption != nil:
		// Section 8.1 leaves no way to opt out of advertised request
		// encryption.
		return fmt.Errorf("%w: the credential issuer advertises credential request encryption", ErrCredentialEncryptionDisallowed)
	case p.Request == CredentialEncryptionRequired && requestEncryption == nil:
		return fmt.Errorf("%w: the credential issuer advertises no credential_request_encryption", ErrCredentialEncryptionUnavailable)
	case p.Response == CredentialEncryptionRequired && (responseEncryption == nil || requestEncryption == nil):
		return fmt.Errorf("%w: the credential issuer advertises no encrypted credential response", ErrCredentialEncryptionUnavailable)
	case (issuerRequiresResponseEncryption || p.Response == CredentialEncryptionRequired) && !responseEncryptionUsable(responseEncryption):
		return fmt.Errorf("%w: the wallet can use none of the credential response encryption algorithms %v and encodings %v", ErrCredentialEncryptionUnavailable, responseEncryption.AlgValuesSupported, responseEncryption.EncValuesSupported)
	}
	return nil
}
