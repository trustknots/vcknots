package statuslist

import "github.com/trustknots/vcknots/wallet/common"

// Sentinel errors a status check returns. Every failure of this package wraps
// exactly one of them, so a caller branches on the condition with errors.Is, or
// reads the stable code with common.CodeOf, instead of matching message text.
//
// Each condition maps to the sentinel that names it and to no other: a Status
// List Token with the wrong `typ` is not a signature failure, an index past the
// end of the decoded list is not a decoding failure, and an algorithm this
// checker does not accept is not an unresolved key. A consumer that renders a
// verdict to a person, or that decides whether to retry, needs those apart:
// a fetch failure is worth retrying later, a bad signature never is.
var (
	// ErrStatusReferenceInvalid reports that the credential's `status` claim
	// does not carry a usable `status_list` reference: the member is absent or
	// is not a JSON object, `idx` is not an exactly representable non-negative
	// integer, `uri` is not a non-empty string, or the URI is not an absolute
	// https URL without user information and fragment
	// (draft-ietf-oauth-status-list Section 7.1).
	ErrStatusReferenceInvalid = common.NewCodedError("status_reference_invalid", "credential status_list reference is not usable")
	// ErrStatusListFetchFailed reports that the Status List Token could not be
	// retrieved from the referenced URI: the request failed, the endpoint
	// answered with a non-2xx status, a redirect that could not be followed
	// (not a 301, 302, 303, 307 or 308, no Location, a target that is not an
	// https URL, or more than five in a row), the response was not typed
	// application/statuslist+jwt (draft-ietf-oauth-status-list Section 10.1),
	// or the body was empty or larger than the configured cap.
	ErrStatusListFetchFailed = common.NewCodedError("status_list_fetch_failed", "status list token could not be fetched")
	// ErrStatusListTokenTypInvalid reports that the fetched token's protected
	// header does not carry the type draft-ietf-oauth-status-list Section 5.1
	// requires, `typ: "statuslist+jwt"`. The header is read before anything
	// else is trusted, so a document that is not a Status List Token at all is
	// refused by the name it gives itself rather than by a failed signature.
	ErrStatusListTokenTypInvalid = common.NewCodedError("status_list_token_typ_invalid", "status list token typ header is not statuslist+jwt")
	// ErrStatusListTokenInvalid reports that the token is not a well-formed
	// Status List Token: it is not a compact JWS (RFC 7515 Section 7.1), its
	// payload is not a JSON object, it omits a claim
	// draft-ietf-oauth-status-list Section 5.1 makes REQUIRED (`sub`, `iat`,
	// `status_list`), its `sub` does not name the `uri` the credential
	// references, an `iss` it carries is not a non-empty string, or
	// `status_list.bits`, `status_list.lst` or `ttl` is outside the values
	// that section defines.
	ErrStatusListTokenInvalid = common.NewCodedError("status_list_token_invalid", "status list token is not a well-formed status list token")
	// ErrStatusListSignatureInvalid reports that none of the issuer keys
	// resolved for the token verified its signature. The verdict a Status List
	// conveys is only as good as the signature over it, so an unverified token
	// is never read for a status value.
	ErrStatusListSignatureInvalid = common.NewCodedError("status_list_signature_invalid", "status list token signature could not be verified")
	// ErrStatusListIssuerKeyUnresolved reports that no candidate public key was
	// available for the token's `iss`: the resolution hook is absent, it
	// failed, or it returned no key. It is deliberately distinct from
	// ErrStatusListSignatureInvalid, because it describes the caller's
	// configuration or connectivity, not a fault of the issuer.
	ErrStatusListIssuerKeyUnresolved = common.NewCodedError("status_list_issuer_key_unresolved", "status list token issuer keys could not be resolved")
	// ErrStatusListIssuerMismatch reports that the token names, in its `iss`,
	// an external Status Issuer (draft-ietf-oauth-status-list-21 Section 13.5)
	// that Checker.AcceptStatusIssuer refused to accept for the credential. It
	// is decided before any key is resolved. Without that hook no token fails
	// this way: the token is verified under the credential issuer's keys.
	ErrStatusListIssuerMismatch = common.NewCodedError("status_list_issuer_mismatch", "status list token issuer is not accepted for the credential issuer")
	// ErrStatusListTokenExpired reports that the token's `exp`
	// (RFC 7519 Section 4.1.4) has passed, after the configured clock skew is
	// allowed for. draft-ietf-oauth-status-list Section 10.1 lets a Status List
	// Token be cached until then; past it the status it carries is stale and a
	// fresh token must be fetched instead.
	ErrStatusListTokenExpired = common.NewCodedError("status_list_token_expired", "status list token has expired")
	// ErrStatusListDecodeFailed reports that `status_list.lst` could not be
	// turned back into the status list byte string: it is not unpadded
	// base64url (RFC 7515 Section 2), it is not a zlib compressed data stream
	// (RFC 1950) carrying DEFLATE data, or it inflates to more than the
	// configured cap. The cap is enforced while inflating, so a compression
	// bomb is stopped by the reader rather than by a check afterwards.
	ErrStatusListDecodeFailed = common.NewCodedError("status_list_decode_failed", "status list could not be decoded")
	// ErrStatusListIndexOutOfRange reports that the referenced index lies past
	// the end of the decoded status list. It names a disagreement between the
	// credential and the Status List its issuer published, which is a different
	// fault from a list that could not be decoded at all.
	ErrStatusListIndexOutOfRange = common.NewCodedError("status_list_index_out_of_range", "status list index is outside the decoded list")
	// ErrStatusListAlgorithmUnsupported reports that the token's `alg` header
	// is not one of the signature algorithms this checker accepts. It is
	// answered from the protected header alone, before any key is resolved and
	// before any signature is checked, so that the MAC algorithms of RFC 7518
	// Section 3.2 and the unsigned `none` of RFC 7515 Section 3.6 can never
	// reach the verification path: neither authenticates an issuer to a wallet
	// that holds only public keys.
	ErrStatusListAlgorithmUnsupported = common.NewCodedError("status_list_alg_unsupported", "status list token alg header is not an accepted signing algorithm")
	// ErrStatusListCertificateRejected reports that the token's x5c header
	// does not satisfy the x5c rules of the Checker's profile
	// (profile.Options.StatusListTokenX5C, HAIP 1.0 Section 6.1): the header
	// carries no x5c or a malformed one where the rules apply, its leaf is
	// self-signed, its chain includes a trust anchor (reported by the key
	// resolution hook), or the key the token would be verified under is not
	// the x5c leaf's.
	ErrStatusListCertificateRejected = common.NewCodedError("status_list_certificate_rejected", "status list token x5c header does not satisfy the profile")
	// ErrStatusListInsecureTransportForbidden reports that the Checker
	// (Checker.Experimental), or the resolution behind its ResolveIssuerKeys
	// hook, carries an experimental transport relaxation that the Checker's
	// profile forbids (profile.Options.ForbidExperimental, HAIP 1.0
	// Section 4). It is a configuration error: the Checker's own relaxation is
	// refused before anything is fetched.
	ErrStatusListInsecureTransportForbidden = common.NewCodedError("status_list_insecure_transport_forbidden", "the profile does not permit the experimental transport relaxation")
)
