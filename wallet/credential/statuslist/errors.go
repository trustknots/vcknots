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
	// https URL without query and fragment
	// (draft-ietf-oauth-status-list Section 7.1).
	ErrStatusReferenceInvalid = common.NewCodedError("status_reference_invalid", "credential status_list reference is not usable")
	// ErrStatusListFetchFailed reports that the Status List Token could not be
	// retrieved from the referenced URI: the request failed, the endpoint
	// answered with a redirect or a non-2xx status, the response was not typed
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
	// draft-ietf-oauth-status-list Section 5.1 makes REQUIRED (`iss`, `sub`,
	// `iat`, `status_list`), its `sub` does not name the URI it was fetched
	// from, or `status_list.bits`, `status_list.lst` or `ttl` is outside the
	// values that section defines.
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
	// ErrStatusListIssuerMismatch reports that the token's `iss` is not the
	// issuer of the credential being checked, and Checker.AcceptStatusIssuer
	// did not accept it as a Status Issuer for that credential, or that no
	// credential issuer was given. It is decided before any key is resolved.
	ErrStatusListIssuerMismatch = common.NewCodedError("status_list_issuer_mismatch", "status list token issuer is not the credential issuer")
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
)
