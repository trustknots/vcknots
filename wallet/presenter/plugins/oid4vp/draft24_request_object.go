package oid4vp

import (
	"fmt"
)

// withRequestObject authenticates a Draft 24 Request Object and loads its
// claims. The key that verifies it comes from what the Client Identifier
// Scheme names (Draft 24 §5.10.4): the x5c chain for x509_san_dns, which
// Experimental.InsecureSkipX509Verify reduces to the binding and
// signature checks, the attestation for verifier_attestation, the Trust Chain
// for an https Entity Identifier, and the registration for a pre-registered
// client. Draft 24 §5.1
// forbids the client_metadata keys: "Public keys included in this parameter
// MUST NOT be used to verify the signature of signed Authorization Requests",
// and the redirect_uri scheme states "The Authorization Request MUST NOT be
// signed", so such a Request Object is refused.
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

	clientID, err := b.parseClientID(b.req.ClientID)
	if err != nil {
		b.errValidation = err
		return b
	}
	switch clientID.prefix {
	case OID4VPClientIDPrefixVerifierAttestation, OID4VPClientIDPrefixOIDFederation:
		// The keys that may sign these Request Objects come from the
		// attestation or the Trust Chain, never from client_metadata.
		if b.requestObjectValidation == nil {
			err = fmt.Errorf("%w: %q", ErrRequestObjectClientAuthUnsupported, clientID.prefix)
		} else if clientID.prefix == OID4VPClientIDPrefixVerifierAttestation {
			err = b.authenticateVerifierAttestationRequestObject(parsedJWT, clientID, options)
		} else {
			err = b.authenticateFederationRequestObject(obj, parsedJWT, clientID, options)
		}
	case OID4VPClientIDPrefixX509SanDNS:
		err = b.authenticateX509RequestObject(obj, parsedJWT, options, !b.insecureSkipX509Verify)
	case OID4VPClientIDPrefixPreRegistered:
		err = b.authenticatePreRegisteredRequestObject(parsedJWT, options)
	case OID4VPClientIDPrefixRedirectURI:
		err = newAuthorizationRequestError(InvalidRequestError, "%w: the redirect_uri Client Identifier Scheme must not be signed", ErrRequestObjectClientAuthUnsupported)
	default:
		err = fmt.Errorf("%w: %q", ErrRequestObjectClientAuthUnsupported, clientID.prefix)
	}
	if err != nil {
		b.errValidation = err
	}
	return b
}
