package jose

import (
	"crypto/rsa"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/trustknots/vcknots/wallet/common"
)

// MinimumRSAModulusBits is the smallest RSA modulus a JWS signature is
// verified under. RFC 7518 Section 3.3 states for RSASSA-PKCS1-v1_5, and
// Section 3.5 repeats for RSASSA-PSS, that "A key of size 2048 bits or larger
// MUST be used with these algorithms".
const MinimumRSAModulusBits = 2048

// ErrVerificationKeyTooWeak reports a verification key the library refuses
// before any signature is checked under it: an RSA key whose modulus is
// shorter than MinimumRSAModulusBits (RFC 7518 Sections 3.3 and 3.5).
var ErrVerificationKeyTooWeak = common.NewCodedError("jose_verification_key_too_weak", "verification key is below the minimum strength")

// RequireVerificationKeyStrength refuses a key the JWS algorithms of RFC 7518
// forbid, with ErrVerificationKeyTooWeak. key may be a crypto public key
// (*rsa.PublicKey, rsa.PublicKey), an *rsa.PrivateKey, or a jose.JSONWebKey
// (value or pointer) holding one of them. A jose.JSONWebKeySet (value or
// pointer), from which the JWS library picks the key by kid, is refused when
// any of its keys is. A key of any other type is left to the JWS library,
// which refuses what it cannot use.
func RequireVerificationKeyStrength(key any) error {
	var modulusBits int
	switch typed := key.(type) {
	case jose.JSONWebKeySet:
		for index := range typed.Keys {
			if err := RequireVerificationKeyStrength(typed.Keys[index]); err != nil {
				return err
			}
		}
		return nil
	case *jose.JSONWebKeySet:
		if typed == nil {
			return nil
		}
		return RequireVerificationKeyStrength(*typed)
	case jose.JSONWebKey:
		return RequireVerificationKeyStrength(typed.Key)
	case *jose.JSONWebKey:
		if typed == nil {
			return nil
		}
		return RequireVerificationKeyStrength(typed.Key)
	case *rsa.PublicKey:
		if typed == nil || typed.N == nil {
			return fmt.Errorf("%w: RSA public key has no modulus", ErrVerificationKeyTooWeak)
		}
		modulusBits = typed.N.BitLen()
	case rsa.PublicKey:
		return RequireVerificationKeyStrength(&typed)
	case *rsa.PrivateKey:
		if typed == nil {
			return nil
		}
		return RequireVerificationKeyStrength(&typed.PublicKey)
	default:
		return nil
	}
	if modulusBits < MinimumRSAModulusBits {
		return fmt.Errorf("%w: RSA modulus is %d bits, below the %d bit minimum of RFC 7518 Section 3.3",
			ErrVerificationKeyTooWeak, modulusBits, MinimumRSAModulusBits)
	}
	return nil
}

// VerifySignature verifies signed under key and returns the verified payload,
// after refusing a key RequireVerificationKeyStrength refuses.
//
// Library code that verifies a JWS with go-jose must do so through
// VerifySignature, VerifyMultiSignature or VerifyClaims rather than through
// go-jose's Verify, VerifyMulti or JSONWebToken.Claims directly, so that every
// such signature is held to the same key requirements; the verifier plugins,
// which verify credential proofs without go-jose, apply the same floor
// themselves. A weak key fails with
// ErrVerificationKeyTooWeak rather than with the JWS library's signature
// error, so a caller can tell the two apart.
func VerifySignature(signed *jose.JSONWebSignature, key any) ([]byte, error) {
	if err := RequireVerificationKeyStrength(key); err != nil {
		return nil, err
	}
	return signed.Verify(key)
}

// VerifyMultiSignature is VerifySignature for a JWS that may carry several
// signatures (JWS JSON Serialization, RFC 7515 Section 7.2): it returns the
// index of the signature that verified under key, that signature, and the
// payload, as go-jose's VerifyMulti does.
func VerifyMultiSignature(signed *jose.JSONWebSignature, key any) (int, jose.Signature, []byte, error) {
	if err := RequireVerificationKeyStrength(key); err != nil {
		return -1, jose.Signature{}, nil, err
	}
	return signed.VerifyMulti(key)
}

// VerifyClaims verifies the signature of token under key and decodes its
// claims into out, as go-jose's JSONWebToken.Claims does, after refusing a key
// RequireVerificationKeyStrength refuses. It checks no claim; the caller
// validates exp, aud and the rest.
func VerifyClaims(token *jwt.JSONWebToken, key any, out ...any) error {
	if err := RequireVerificationKeyStrength(key); err != nil {
		return err
	}
	return token.Claims(key, out...)
}
