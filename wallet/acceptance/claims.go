package acceptance

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"slices"
	"strings"
	"time"

	joseutil "github.com/trustknots/vcknots/wallet/common/jose"
	"github.com/trustknots/vcknots/wallet/credential"
)

// checkValidity applies exp and nbf (RFC 7519 §4.1.4, §4.1.5) at now with skew.
func checkValidity(payload map[string]any, now time.Time, skew time.Duration) error {
	if exp, present, err := joseutil.NumericDateClaim(payload, "exp"); err != nil {
		return fmt.Errorf("%w: %w", ErrCredentialParse, err)
	} else if present && !exp.After(now.Add(-skew)) {
		return ErrCredentialExpired
	}
	if nbf, present, err := joseutil.NumericDateClaim(payload, "nbf"); err != nil {
		return fmt.Errorf("%w: %w", ErrCredentialParse, err)
	} else if present && nbf.After(now.Add(skew)) {
		return ErrCredentialNotYetValid
	}
	return nil
}

// checkDisclosureIntegrity requires every SD-JWT disclosure to be referenced
// by exactly one digest in the payload or another disclosure.
func checkDisclosureIntegrity(payload map[string]any, parsed *credential.Credential) error {
	sdAlg := "sha-256"
	if raw, present := payload["_sd_alg"]; present {
		text, ok := raw.(string)
		if !ok {
			return fmt.Errorf("%w: _sd_alg must be a string", ErrSDAlgUnsupported)
		}
		sdAlg = strings.ToLower(text)
		if !slices.Contains(AcceptedSDAlgorithms(), sdAlg) {
			return fmt.Errorf("%w: unsupported _sd_alg %q", ErrSDAlgUnsupported, text)
		}
	}
	if parsed.SDJwt == nil || len(parsed.SDJwt.Disclosures) == 0 {
		return nil
	}
	references := make(map[string]int)
	collectDigestReferences(payload, references)
	for _, disclosure := range parsed.SDJwt.Disclosures {
		collectDigestReferences(disclosure.Value, references)
	}
	for _, disclosure := range parsed.SDJwt.Disclosures {
		digest, err := disclosureDigest(disclosure.EncodedValue, sdAlg)
		if err != nil {
			return err
		}
		switch {
		case references[digest] == 0:
			return fmt.Errorf("%w: disclosure is not referenced by any digest", ErrDisclosureIntegrity)
		case references[digest] > 1:
			return fmt.Errorf("%w: disclosure digest is referenced more than once", ErrDisclosureIntegrity)
		}
	}
	return nil
}

func collectDigestReferences(value any, references map[string]int) {
	switch typed := value.(type) {
	case map[string]any:
		if digest, ok := typed["..."].(string); ok && digest != "" {
			references[digest]++
		}
		if sd, ok := typed["_sd"].([]any); ok {
			for _, entry := range sd {
				if digest, ok := entry.(string); ok && digest != "" {
					references[digest]++
				}
			}
		}
		for _, child := range typed {
			collectDigestReferences(child, references)
		}
	case []any:
		for _, child := range typed {
			collectDigestReferences(child, references)
		}
	}
}

func disclosureDigest(encodedDisclosure, algorithm string) (string, error) {
	var hasher hash.Hash
	switch algorithm {
	case "sha-256":
		hasher = sha256.New()
	case "sha-384":
		hasher = sha512.New384()
	case "sha-512":
		hasher = sha512.New()
	default:
		return "", fmt.Errorf("%w: unsupported disclosure hash algorithm %q", ErrSDAlgUnsupported, algorithm)
	}
	hasher.Write([]byte(encodedDisclosure))
	return base64.RawURLEncoding.EncodeToString(hasher.Sum(nil)), nil
}
