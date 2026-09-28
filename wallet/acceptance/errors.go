package acceptance

import "github.com/trustknots/vcknots/wallet/common"

// Sentinel errors wrapped at each acceptance failure, so a caller branches
// with errors.Is. An untrusted, revoked or unknown-revocation issuer
// certificate chain is reported with the typed errors of wallet/common/x509
// (*x509.SigningChainError, *x509.CRLCheckError) instead.
var (
	// ErrPolicyRequired reports that a credential was about to be accepted
	// without a Policy.
	ErrPolicyRequired = common.NewCodedError("credential_acceptance_policy_required", "credential acceptance policy is required")
	// ErrCredentialParse reports that the credential does not deserialize, or
	// its issuer JWT is not three base64url parts of the JSON it must hold.
	ErrCredentialParse = common.NewCodedError("credential_parse_failed", "credential could not be parsed")
	// ErrCredentialTypInvalid reports an issuer JWT typ the serialization does
	// not allow (SD-JWT VC §2.2.1: dc+sd-jwt; vc+sd-jwt only under
	// profile.Draft13), an SD-JWT VC without a vct (§2.2.2.3), or a vct other
	// than Policy.ExpectedSDJWTVCType.
	ErrCredentialTypInvalid = common.NewCodedError("credential_typ_invalid", "credential typ header is not supported")
	// ErrCredentialAlgUnsupported reports an alg header that is missing,
	// "none", absent from Policy.SigningAlgorithms, or implemented by no
	// verifier plugin.
	ErrCredentialAlgUnsupported = common.NewCodedError("credential_alg_unsupported", "credential signing algorithm is not accepted")
	// ErrHolderBindingMissing reports that Policy.RequireHolderBinding is set
	// and the credential has no cnf, or has one while no holder key was given.
	ErrHolderBindingMissing = common.NewCodedError("credential_holder_binding_missing", "credential does not contain a cnf holder binding")
	// ErrHolderBindingMismatch reports that cnf.jwk is not the holder key,
	// compared by RFC 7638 thumbprint.
	ErrHolderBindingMismatch = common.NewCodedError("credential_holder_binding_mismatch", "credential is bound to a different holder key")
	// ErrHolderBindingConfirmationUnsupported reports a cnf without a jwk
	// member (for example cnf.kid). Only cnf.jwk gives the wallet the key it
	// must prove possession of.
	ErrHolderBindingConfirmationUnsupported = common.NewCodedError("credential_holder_binding_unsupported", "credential cnf confirmation method is not supported; only cnf.jwk is accepted")
	// ErrIssuerKeyUnresolved reports that no issuer key could be obtained:
	// the policy configures no way to find one, or the resolver failed or
	// returned no usable key. The signature has not been checked.
	ErrIssuerKeyUnresolved = common.NewCodedError("issuer_key_unresolved", "issuer key could not be resolved")
	// ErrIssuerSignatureInvalid reports that no candidate issuer key verifies
	// the signature.
	ErrIssuerSignatureInvalid = common.NewCodedError("issuer_signature_invalid", "issuer signature could not be verified")
	// ErrIssuerDNSBindingFailed reports an x5c credential whose iss the leaf
	// certificate is not bound to: an https iss whose host the leaf names in
	// no dNSName or URI subject alternative name, a DID iss (authenticated by
	// its DID document, never by x5c), or an iss that is not an https URL.
	ErrIssuerDNSBindingFailed = common.NewCodedError("issuer_dns_binding_failed", "issuer certificate is not bound to the issuer host")
	// ErrCredentialExpired reports an exp in the past of the policy clock.
	ErrCredentialExpired = common.NewCodedError("credential_expired", "credential has expired")
	// ErrCredentialNotYetValid reports an nbf in the future of the policy clock.
	ErrCredentialNotYetValid = common.NewCodedError("credential_not_yet_valid", "credential is not yet valid")
	// ErrDisclosureIntegrity reports an SD-JWT disclosure that is not covered
	// by exactly one digest.
	ErrDisclosureIntegrity = common.NewCodedError("disclosure_integrity_failed", "SD-JWT disclosure integrity check failed")
	// ErrSDAlgUnsupported reports an _sd_alg that is not a string or not one
	// of AcceptedSDAlgorithms.
	ErrSDAlgUnsupported = common.NewCodedError("sd_alg_unsupported", "credential _sd_alg is not supported")
	// ErrIssuerX5CRequired reports an SD-JWT VC without x5c under
	// profile.Options.IssuerX5C.Require (HAIP §6.1.1).
	ErrIssuerX5CRequired = common.NewCodedError("issuer_x5c_required", "the credential carries no issuer signing certificate in the x5c header")
	// ErrIssuerX5CTrustAnchor reports an x5c chain that carries a configured
	// trust anchor under profile.Options.IssuerX5C.ExcludeAnchor (HAIP
	// §6.1.1).
	ErrIssuerX5CTrustAnchor = common.NewCodedError("issuer_x5c_trust_anchor", "the x5c header of the credential includes the trust anchor certificate")
	// ErrIssuerCertificateSelfSigned reports a self-signed issuer signing
	// certificate under profile.Options.IssuerX5C.RejectSelfSigned (HAIP
	// §6.1.1).
	ErrIssuerCertificateSelfSigned = common.NewCodedError("issuer_certificate_self_signed", "the issuer signing certificate must not be self-signed")
)
