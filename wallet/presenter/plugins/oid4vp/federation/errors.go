// Package federation implements the Relying Party side of OpenID Federation
// 1.0 that an OpenID4VP Wallet needs to authenticate a Verifier using the
// openid_federation Client Identifier Prefix (OpenID4VP 1.0 Section 5.9.3):
// Entity Statement validation (OpenID Federation 1.0 Section 3), Trust Chain
// discovery and validation (Sections 4, 9, 8.1 and 10), metadata policy
// resolution and application (Section 6.1), constraints (Section 6.2) and the
// derivation of the final Verifier metadata.
//
// The package holds no state across resolutions: a Resolver memoizes the
// Entity Statements it fetched only for the duration of one call.
package federation

import (
	"fmt"

	"github.com/trustknots/vcknots/wallet/common"
)

// Sentinel errors this package returns. Every failure wraps exactly one of
// them, so an integrator branches with errors.Is or common.CodeOf instead of
// matching message text. Messages never carry key material or response
// bodies.
var (
	// ErrTrustAnchorNotConfigured reports that no Trust Anchor is configured,
	// so no Trust Chain can be accepted at all.
	ErrTrustAnchorNotConfigured = common.NewCodedError("openid_federation_trust_anchor_not_configured", "no OpenID Federation trust anchor is configured")
	// ErrStatementFetchFailed reports that an Entity Statement could not be
	// retrieved under the network policy: a non-https or malformed URL, a
	// refused host, a redirect, a non-success status, the wrong media type, an
	// empty or oversized body, or a transport failure (OpenID Federation 1.0
	// Sections 8.1 and 9).
	ErrStatementFetchFailed = common.NewCodedError("openid_federation_statement_fetch_failed", "OpenID Federation entity statement could not be fetched")
	// ErrTrustChainInvalid reports that a Trust Chain failed validation: an
	// Entity Statement is malformed, carries an unsupported critical claim or
	// operator, is outside its validity, is not signed by the expected key, the
	// chain topology is broken, a constraint is violated, or it does not end
	// at a configured Trust Anchor (OpenID Federation 1.0 Sections 3, 4, 6.2
	// and 10.2).
	ErrTrustChainInvalid = common.NewCodedError("openid_federation_trust_chain_invalid", "OpenID Federation trust chain is invalid")
	// ErrTrustChainUnresolved reports that Trust Chain discovery (OpenID
	// Federation 1.0 Section 10.1) built no chain that reaches a configured
	// Trust Anchor within the Resolver's bounds (depth, fetches, duration),
	// including when an Entity Configuration on the way was unusable for
	// discovery.
	ErrTrustChainUnresolved = common.NewCodedError("openid_federation_trust_chain_unresolved", "OpenID Federation trust chain could not be resolved to a configured trust anchor")
	// ErrMetadataPolicyInvalid reports that the metadata policies of a Trust
	// Chain are malformed, cannot be combined, or reject the metadata they are
	// applied to (OpenID Federation 1.0 Section 6.1).
	ErrMetadataPolicyInvalid = common.NewCodedError("openid_federation_metadata_policy_invalid", "OpenID Federation metadata policy is invalid")
	// ErrMetadataDerivationFailed reports that the final metadata of an Entity
	// could not be derived from a valid Trust Chain: the requested Entity Type
	// metadata is missing or malformed, the Entity Type is disallowed by a
	// constraint, or display metadata is not an absolute URI.
	ErrMetadataDerivationFailed = common.NewCodedError("openid_federation_metadata_derivation_failed", "OpenID Federation metadata could not be derived")
	// ErrResponseURINotRegistered reports that the endpoint an Authorization
	// Response would be sent to is not one of the redirect_uris of the
	// Verifier metadata the Trust Chain produced.
	ErrResponseURINotRegistered = common.NewCodedError("openid_federation_response_uri_not_registered", "response endpoint is not registered in the OpenID Federation verifier metadata")
)

// failure wraps sentinel with a message describing the specific condition.
func failure(sentinel error, format string, args ...any) error {
	return fmt.Errorf("%w: %s", sentinel, fmt.Sprintf(format, args...))
}
