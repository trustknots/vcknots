package oid4vp

import (
	"fmt"

	"github.com/trustknots/vcknots/wallet/presenter/plugins/oid4vp/federation"
)

// authenticateUnsignedFederationRequest handles an openid_federation request
// in plain parameters. It is refused unless the Wallet opted in with
// FederationTrustOptions.AllowUnsignedRequests; then the Trust Chain supplies
// the Verifier metadata (OID4VP 1.0 §5.9.3) and the response endpoint must be
// one of its redirect_uris. Nothing authenticates the request parameters
// themselves.
func (b *requestCore) authenticateUnsignedFederationRequest(parseClientID func(string) (*OID4VPClientID, error), params map[string]any) error {
	clientID, err := parseClientID(b.req.ClientID)
	if err != nil || clientID.prefix != OID4VPClientIDPrefixOIDFederation {
		return nil
	}
	options, err := b.requestObjectValidationOptions()
	if err != nil {
		return err
	}
	if options.Federation == nil || len(options.Federation.TrustAnchors) == 0 {
		return fmt.Errorf("%w: no OpenID Federation trust anchor is configured", federation.ErrTrustAnchorNotConfigured)
	}
	if !options.Federation.AllowUnsignedRequests {
		return newAuthorizationRequestError(InvalidRequestError, "%w: openid_federation", ErrRequestObjectSignatureRequired)
	}
	var carried []string
	if raw, present := params["trust_chain"]; present && raw != nil && raw != "" {
		carried, err = federation.ParseTrustChainParameter(raw)
		if err != nil {
			return err
		}
	}
	trust, err := b.federationResolver(options).ResolveVerifierTrust(
		b.context(),
		clientID.original,
		carried,
		options.Federation.PreferredLocales,
	)
	if err != nil {
		return err
	}
	if err := federation.AssertResponseURIAllowed(trust.Metadata, b.req.responseEndpoint()); err != nil {
		return err
	}
	if err := b.adoptFederationVerifierMetadata(trust.Metadata); err != nil {
		return err
	}
	b.req.VerifierFederation = newFederationEvidence(trust)
	return nil
}
