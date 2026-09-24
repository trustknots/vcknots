package oid4vp

import (
	"fmt"

	commonJOSE "github.com/trustknots/vcknots/wallet/common/jose"
)

// withRequestObject authenticates a Draft 24 Request Object and loads its
// claims. X.509 Client Identifiers use the shared X.509 authentication, which
// InsecureSkipX509Verify reduces to the binding and signature checks.
// verifier_attestation and openid_federation are authenticated as on the 1.0
// wire. Any other Client Identifier is verified with a client_metadata key,
// which Draft 24 permits.
func (b *draft24RequestBuilder) withRequestObject(obj string) *draft24RequestBuilder {
	if b.errValidation != nil {
		return b
	}
	b.requestObject = obj

	options, err := b.requestObjectValidationOptions()
	if err != nil {
		b.errValidation = err
		return b
	}
	b.adoptCallerWalletNonce()

	parsedJWT, claims, err := decodeRequestObject(obj, resolveRequestObjectAlgorithms(options))
	if err != nil {
		b.errValidation = err
		return b
	}

	b.setParams(claims)
	if err := b.validate(); err != nil {
		b.errValidation = err
		return b
	}

	clientID, clientIDErr := b.parseClientID(b.req.ClientID)
	if clientIDErr == nil {
		switch clientID.prefix {
		case OID4VPClientIDPrefixVerifierAttestation, OID4VPClientIDPrefixOIDFederation:
			// The keys that may sign these Request Objects come from the
			// attestation or the Trust Chain, never from client_metadata.
			if b.requestObjectValidation == nil {
				b.errValidation = fmt.Errorf("%w: %q", ErrRequestObjectClientAuthUnsupported, clientID.prefix)
				return b
			}
			if clientID.prefix == OID4VPClientIDPrefixVerifierAttestation {
				err = b.authenticateVerifierAttestationRequestObject(parsedJWT, clientID, options)
			} else {
				err = b.authenticateFederationRequestObject(obj, parsedJWT, clientID, options)
			}
			if err != nil {
				b.errValidation = err
			}
			return b
		case OID4VPClientIDPrefixX509Hash, OID4VPClientIDPrefixX509SanDNS:
			if err := b.authenticateX509RequestObject(obj, parsedJWT, options, !b.insecureSkipX509Verify); err != nil {
				b.errValidation = err
			}
			return b
		}
	}

	// Draft 24 JAR: the Request Object is signed with a key the Verifier
	// publishes in client_metadata.
	if b.req.ClientMetadata == nil {
		b.errValidation = fmt.Errorf("client_metadata is required for JWT request object verification")
		return b
	}
	k, err := b.req.ClientMetadata.FetchKeyWithKID(parsedJWT.Headers[0].KeyID)
	if err != nil {
		b.errValidation = fmt.Errorf("failed to fetch public key for JWT verification: %w", err)
		return b
	}
	verifiedClaims := make(commonJOSE.Claims)
	if err := parsedJWT.Claims(&k, &verifiedClaims); err != nil {
		b.errValidation = fmt.Errorf("failed to verify JWT signature: %w: %w", err, ErrRequestObjectSignatureInvalid)
		return b
	}
	// The registered claims are judged at the caller's verification time with
	// its ClockSkew; this path never reads aud.
	policy := b.resolveClaimPolicy(options, requestObjectNow(options))
	policy.Audiences = nil
	policy.AudienceOptional = true
	if err := validateRequestObjectClaims(verifiedClaims, policy); err != nil {
		b.errValidation = fmt.Errorf("JWT standard claims validation failed: %w", err)
		return b
	}
	// Reload the parameters from the verified claims.
	b.setParams(verifiedClaims)
	if err := b.validate(); err != nil {
		b.errValidation = err
	}
	return b
}
