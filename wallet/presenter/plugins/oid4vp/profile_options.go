package oid4vp

import (
	"fmt"
	"strings"

	"github.com/trustknots/vcknots/wallet/profile"
)

// enforceProfileOptions applies the profile Options that can only be checked
// once the Authorization Request parameters have been assembled. The zero
// Options (profile.Final) check nothing.
func (b *requestBuilder) enforceProfileOptions() error {
	options := b.options
	// Record the delivery this parse observed itself.
	if b.req.RequestObjectVerification != nil {
		b.req.RequestObjectVerification.Delivery = b.requestSource.delivery()
	}
	// HAIP §5.2: "The Wallet MUST support the Response Mode dc_api.jwt" and
	// "The Wallet MUST support unsigned, signed, and multi-signed requests as
	// defined in Appendices A.3.1 and A.3.2". The request_uri rule of §5.1
	// therefore does not apply to DC API requests.
	if b.requestSource.isDCAPI() {
		// HAIP §5.2: "The Verifier MUST use the Response Mode dc_api.jwt."
		// The unencrypted dc_api mode stays available without the option.
		if options.RequireDCAPIJWT && b.req.ResponseMode != OAuthAuthzReqResponseModeDCAPIJWT {
			return newAuthorizationRequestError(InvalidRequestError, "%w requires the response_mode dc_api.jwt for Digital Credentials API requests", profile.Refused("RequireDCAPIJWT"))
		}
		if b.requestSource == sourceDCAPIUnsigned {
			// An unsigned request has no Verifier client_id to authenticate.
			return nil
		}
		return b.requireAllowedClientIDPrefix()
	}
	if options.RequireSignedRequestByReference && b.requestSource != sourceReference {
		// HAIP §5.1: "Signed Authorization Requests MUST be used by utilizing
		// JAR with the request_uri parameter".
		return errRequestURIRequired()
	}
	if options.RequireDirectPostJWT && b.req.ResponseMode != OAuthAuthzReqResponseModeDirectPostJWT {
		// HAIP §5.1: "Response encryption MUST be used by utilizing response
		// mode direct_post.jwt".
		return newAuthorizationRequestError(InvalidRequestError, "%w requires response_mode direct_post.jwt", profile.Refused("RequireDirectPostJWT"))
	}
	return b.requireAllowedClientIDPrefix()
}

// errRequestURIRequired is the refusal of a redirect-based request that
// this library did not fetch from request_uri itself, under
// Options.RequireSignedRequestByReference (HAIP 1.0 §5.1).
func errRequestURIRequired() error {
	return fmt.Errorf("%w: %w",
		newAuthorizationRequestError(InvalidRequestError, "%w requires a signed Authorization Request delivered by request_uri", profile.Refused("RequireSignedRequestByReference")),
		ErrRequestURIRequired)
}

// requireAllowedClientIDPrefix applies Options.AllowedClientIDPrefixes and
// Options.RequestObjectX5C.Require to the Client Identifier of a request that
// names a Verifier.
func (b *requestBuilder) requireAllowedClientIDPrefix() error {
	allowed := b.options.AllowedClientIDPrefixes
	requireX5C := b.options.RequestObjectX5C.Require && b.requestSource != sourceQuery
	if allowed == 0 && !requireX5C {
		return nil
	}
	clientID, err := parseOID4VPClientID(b.req.ClientID)
	if err != nil {
		return err
	}
	if !allowed.Allows(string(clientID.prefix)) {
		// HAIP §5: "For signed requests, the Verifier MUST use, and the Wallet
		// MUST accept the Client Identifier Prefix x509_hash".
		return newAuthorizationRequestError(InvalidRequestError, "%w requires the %s Client Identifier Prefix", profile.Refused("AllowedClientIDPrefixes"), strings.ReplaceAll(allowed.String(), ",", " or "))
	}
	if requireX5C && clientID.prefix != OID4VPClientIDPrefixX509Hash && clientID.prefix != OID4VPClientIDPrefixX509SanDNS {
		// HAIP §5: a signed request is authenticated through the x5c chain of
		// an X.509 Client Identifier.
		return newAuthorizationRequestError(InvalidRequestError, "%w requires a signed request authenticated with x5c, got the %s Client Identifier Prefix", profile.Refused("RequestObjectX5C.Require"), clientID.prefix)
	}
	return nil
}
