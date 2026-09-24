package issuerkeys

import (
	"errors"

	"github.com/trustknots/vcknots/wallet/common"
)

// Sentinel errors the issuer key ladder reports. A caller branches on the
// condition with errors.Is, or reads the stable code with common.CodeOf,
// instead of matching message text.
//
// Most of them never leave Resolve as its return value: a rung that fails is
// recorded in Resolution.Diagnostics and the ladder carries on, because another
// rung may still establish the key. They are still errors rather than plain
// strings because the rung code works with them internally, and because a
// caller that drives one mechanism by hand - resolving a DID, say - gets the
// same vocabulary as the ladder.
var (
	// ErrIssuerURLNotAllowed reports a URL the resolver refuses to request:
	// one that does not parse, that is not https (nor http while AllowHTTP is
	// set), or that carries a query or a fragment. A metadata location is a
	// fixed, well-known path; a query or fragment on it is a sign the value
	// was built from something other than the issuer identifier.
	ErrIssuerURLNotAllowed = common.NewCodedError("issuer_keys_url_not_allowed", "issuer key metadata URL is not allowed")
	// ErrIssuerMetadataFetchFailed reports that a metadata document could not
	// be retrieved: the request failed, the origin answered a redirect or a
	// non-2xx status, it did not label the body as JSON, or the body was
	// empty or exceeded the configured cap.
	ErrIssuerMetadataFetchFailed = common.NewCodedError("issuer_keys_metadata_fetch_failed", "issuer key metadata could not be retrieved")
	// ErrIssuerMetadataInvalid reports that a retrieved metadata document is
	// not usable: not a JSON object, missing a member the document's own
	// specification requires, or carrying no key this library can read.
	ErrIssuerMetadataInvalid = common.NewCodedError("issuer_keys_metadata_invalid", "issuer key metadata is not usable")
	// ErrJWTVCIssuerMismatch reports that a JWT VC Issuer Metadata document
	// names an issuer other than the credential's own `iss`. The IETF SD-JWT VC
	// specification requires the document's `issuer` member to equal the
	// Issuer identifier the document was retrieved for, so a mismatch means the
	// document does not speak for this credential.
	ErrJWTVCIssuerMismatch = common.NewCodedError("issuer_keys_jwt_vc_issuer_mismatch", "JWT VC Issuer Metadata names another issuer")
	// ErrDIDResolutionFailed reports that the DID named by the credential could
	// not be resolved to any verification key.
	ErrDIDResolutionFailed = common.NewCodedError("issuer_keys_did_resolution_failed", "DID could not be resolved to a verification key")
	// ErrDIDHostNotBound reports that a did:web document would be retrieved
	// from a host other than the Credential Issuer's. Nothing ties an arbitrary
	// web origin's DID document to this issuance, so the document is not
	// requested at all.
	ErrDIDHostNotBound = common.NewCodedError("issuer_keys_did_web_host_not_bound", "did:web host is not the Credential Issuer host")
	// ErrDIDOnlyTrustUnsupported reports that a DID resolved to a key, but
	// nothing binds that DID to the Credential Issuer. Resolving a DID proves
	// only that whoever controls the DID signed the credential; accepting it on
	// that basis alone would let any DID controller issue in the Credential
	// Issuer's name.
	ErrDIDOnlyTrustUnsupported = common.NewCodedError("issuer_keys_did_only_trust_unsupported", "DID is not bound to the Credential Issuer")
	// ErrNoIssuerKeyResolved reports that every rung of the ladder finished
	// without producing a candidate key.
	ErrNoIssuerKeyResolved = common.NewCodedError("issuer_keys_unresolved", "no issuer key could be resolved")
)

// mechanismError is an error whose message is a short description authored by
// this package, taken from a fixed vocabulary, and safe to show.
//
// Nothing in a mechanism failure may come from the other side of the network.
// An upstream error string can carry a URL, a response body, or - when it comes
// from a JOSE library - the coordinates of a key that failed to parse, and a
// MechanismDiagnostic is meant to be rendered, logged and shipped. So the rungs
// never wrap an upstream error's text: they name the condition themselves, and
// this type carries that name alongside the sentinel that classifies it.
type mechanismError struct {
	code   string
	reason string
	cause  error
}

func (e *mechanismError) Error() string { return e.reason }

// ErrorCode returns the code of the sentinel this failure was classified with,
// so common.CodeOf reports the condition rather than "unclassified".
func (e *mechanismError) ErrorCode() string { return e.code }

func (e *mechanismError) Unwrap() error { return e.cause }

// newMechanismError classifies reason with sentinel. reason must be authored
// here, never taken from an upstream error, a response body or a URL.
func newMechanismError(sentinel error, reason string) error {
	return &mechanismError{code: sentinelCode(sentinel), reason: reason, cause: sentinel}
}

// failureReason returns the short description to record in a diagnostic.
//
// An error this package built carries its own authored description. Anything
// else - an error from a caller-supplied HTTP client or DIDResolver - is
// reduced to a fixed string, because its text is outside this package's control
// and may carry key material.
func failureReason(err error) string {
	if err == nil {
		return ""
	}
	var mechanism *mechanismError
	if errors.As(err, &mechanism) {
		return mechanism.reason
	}
	return "mechanism failed"
}

// UnresolvedError reports that the whole ladder produced no candidate key, and
// carries what each rung did.
//
// The diagnostics travel on the error rather than on a Resolution, because a
// run that resolves nothing has no resolution to return; a caller that wants to
// tell the user which mechanism was switched off, which one was never
// applicable and which one was tried and failed reads them with errors.As.
type UnresolvedError struct {
	// Diagnostics reports one entry per rung of the ladder, in ladder order.
	Diagnostics []MechanismDiagnostic
}

// Error summarises the rungs. Every part of the message is authored by this
// package, so it carries no key material and no upstream response text.
func (e *UnresolvedError) Error() string {
	summary := "no issuer key could be resolved"
	for _, diagnostic := range e.Diagnostics {
		summary += "; " + diagnostic.Mechanism + ": "
		switch {
		case diagnostic.Failure != "":
			summary += diagnostic.Failure
		case diagnostic.CandidateCount > 0:
			summary += "produced candidates"
		default:
			summary += "no candidates"
		}
	}
	return summary
}

// ErrorCode names the condition with ErrNoIssuerKeyResolved's code.
func (e *UnresolvedError) ErrorCode() string { return sentinelCode(ErrNoIssuerKeyResolved) }

// Unwrap lets errors.Is(err, ErrNoIssuerKeyResolved) recognise this error.
func (e *UnresolvedError) Unwrap() error { return ErrNoIssuerKeyResolved }

// DIDOnlyTrustError reports that a DID resolved to a key but nothing binds that
// DID to the Credential Issuer, and carries what the ladder had done up to that
// point.
//
// The ladder stops there instead of trying the issuer metadata rung, so the
// diagnostics end with the DID rung. Its DisabledBy names the binding switches
// that were off, which is what a holder can change to let the DID be bound.
type DIDOnlyTrustError struct {
	// Diagnostics reports one entry per rung the ladder ran, in ladder order.
	Diagnostics []MechanismDiagnostic
}

// Error states the condition. It carries no DID, key or URL.
func (e *DIDOnlyTrustError) Error() string {
	return "DID is not bound to the Credential Issuer by issuer metadata, a signed credential_issuer or a DID Configuration"
}

// ErrorCode names the condition with ErrDIDOnlyTrustUnsupported's code.
func (e *DIDOnlyTrustError) ErrorCode() string { return sentinelCode(ErrDIDOnlyTrustUnsupported) }

// sentinelCode returns the code of one of this package's sentinels, so an error
// type that reports the same condition never spells the code a second time.
func sentinelCode(sentinel error) string {
	code, _ := common.CodeOf(sentinel)
	return code
}

// Unwrap lets errors.Is(err, ErrDIDOnlyTrustUnsupported) recognise this error.
func (e *DIDOnlyTrustError) Unwrap() error { return ErrDIDOnlyTrustUnsupported }
