package wallet

import (
	"context"
	"errors"
	"fmt"

	"github.com/trustknots/vcknots/wallet/acceptance"
	"github.com/trustknots/vcknots/wallet/common"
	"github.com/trustknots/vcknots/wallet/internal/jwtproof"
	receiverOid4vci "github.com/trustknots/vcknots/wallet/receiver/plugins/oid4vci"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// Aliases of sentinels declared by sub-packages, so errors.Is holds at either
// import path.
var (
	// ErrCredentialAcceptancePolicyRequired reports that Config.CredentialAcceptance
	// is nil on a path that must authenticate the issuer before storing.
	ErrCredentialAcceptancePolicyRequired = acceptance.ErrPolicyRequired
	ErrHTTPRedirectNotAllowed             = receiverOid4vci.ErrHTTPRedirectNotAllowed
	// ErrProofAlgorithmNotSupported reports that the holder key's algorithm is
	// not in proof_signing_alg_values_supported (OpenID4VCI 1.0 Appendix F.1).
	ErrProofAlgorithmNotSupported = jwtproof.ErrProofAlgorithmNotSupported
	// ErrProofTypeUnsupported reports a Credential Configuration whose
	// proof_types_supported lacks jwt, the only key proof the wallet builds.
	ErrProofTypeUnsupported           = receiverTypes.ErrInvalidProofType
	ErrDPoPRequired                   = receiverOid4vci.ErrDPoPRequired
	ErrIssuerIdentifierMismatch       = receiverOid4vci.ErrIssuerIdentifierMismatch
	ErrIssuerMetadataSignatureInvalid = receiverOid4vci.ErrIssuerMetadataSignatureInvalid
	ErrIssuerMetadataSubjectMismatch  = receiverOid4vci.ErrIssuerMetadataSubjectMismatch
	ErrIssuerMetadataLeafDNSMismatch  = receiverOid4vci.ErrIssuerMetadataLeafDNSMismatch
	ErrIssuerMetadataExpired          = receiverOid4vci.ErrIssuerMetadataExpired
	// ErrIssuerMetadataSignatureRequired reports that signed metadata was
	// required and none was obtained.
	ErrIssuerMetadataSignatureRequired = receiverOid4vci.ErrIssuerMetadataSignatureRequired
	ErrCredentialResponsePlaintext     = receiverTypes.ErrCredentialResponsePlaintext
	ErrCredentialResponseDecrypt       = receiverTypes.ErrCredentialResponseDecrypt
	ErrCredentialResponseShape         = receiverTypes.ErrCredentialResponseShape
)

// Issuance conditions.
var (
	// ErrIssuanceVersionMismatch reports a state of the other OpenID4VCI
	// version: a Draft 13 state given to a 1.0 method or the reverse.
	ErrIssuanceVersionMismatch = common.NewCodedError("issuance_version_mismatch", "issuance state belongs to another OpenID4VCI version")
	// ErrIssuanceStateMismatch reports a state that is incomplete or does not
	// fit the wallet: another client_id, redirect_uri or DPoP key than Config
	// names, or an authorization server the issuer no longer delegates to.
	ErrIssuanceStateMismatch = common.NewCodedError("issuance_state_mismatch", "issuance state does not match the wallet or the issuer")
	// ErrUnknownCredentialConfiguration reports a credential_configuration_id
	// that the offer or the issuer metadata does not list.
	ErrUnknownCredentialConfiguration = common.NewCodedError("unknown_credential_configuration", "credential_configuration_id is not offered by the issuer")
	// ErrKeyAttestationRequired reports that the Credential Request needs a key
	// attestation neither the request nor Config.Attestation.Key supplies. It
	// is carried by *KeyAttestationRequiredError.
	ErrKeyAttestationRequired = common.NewCodedError("key_attestation_required", "credential request requires a key attestation the wallet cannot mint")
	// ErrKeyAttestationNonceRejected reports that a supplied key attestation
	// carries another nonce than the Credential Request must, or that the
	// issuer answered invalid_nonce. It is carried by
	// *KeyAttestationRequiredError.
	ErrKeyAttestationNonceRejected = common.NewCodedError("key_attestation_nonce_rejected", "key attestation nonce was rejected")
	// ErrNonceEndpointRequired reports a key attestation under HAIP from an
	// issuer without a Nonce Endpoint (HAIP Section 4.5.1).
	ErrNonceEndpointRequired = common.NewCodedError("nonce_endpoint_required", "key attestation requires a c_nonce but the issuer advertises no nonce_endpoint")
	// ErrPreAuthorizedGrantMissing reports an offer without a usable
	// pre-authorized_code grant.
	ErrPreAuthorizedGrantMissing = common.NewCodedError("pre_authorized_grant_missing", "credential offer carries no pre-authorized_code grant")
	// ErrTransactionCodeRequired reports a tx_code the offer asks for and the
	// request lacks (OpenID4VCI 1.0 Section 6.1).
	ErrTransactionCodeRequired = common.NewCodedError("transaction_code_required", "credential offer requires a transaction code")
	// ErrTokenTypeUnsupported reports a token_type that is neither Bearer nor
	// DPoP, or a DPoP token the wallet holds no key for.
	ErrTokenTypeUnsupported = common.NewCodedError("token_type_unsupported", "token response token_type is not supported")
	// ErrDPoPKeyMismatch reports a DPoP-bound token whose key is not
	// Config.DPoP.Key (RFC 9449 Section 5).
	ErrDPoPKeyMismatch = common.NewCodedError("dpop_key_mismatch", "token grant is bound to a different DPoP key")
	// ErrDPoPKeyRequired reports a HAIP issuance without Config.DPoP.Key (HAIP
	// Section 4: sender-constrained tokens).
	ErrDPoPKeyRequired = common.NewCodedError("dpop_key_required", "a DPoP key is required")
	// ErrAuthorizationDetailsMissing reports a Token Response without a usable
	// openid_credential authorization_details entry although the request used
	// authorization_details (OpenID4VCI 1.0 Section 6.2).
	ErrAuthorizationDetailsMissing = common.NewCodedError("authorization_details_missing", "token response carries no usable authorization_details")
	// ErrCredentialResponseMultipleCredentials reports more credentials than
	// key proofs were sent.
	ErrCredentialResponseMultipleCredentials = common.NewCodedError("credential_response_multiple_credentials", "credential response carries more credentials than were requested")
	// ErrCredentialEncryptionUnavailable reports that the holder's
	// CredentialEncryptionPolicy requires an encryption the issuer does not
	// offer.
	ErrCredentialEncryptionUnavailable = common.NewCodedError("credential_encryption_unavailable", "the credential issuer does not offer the credential encryption this wallet requires")
	// ErrCredentialEncryptionDisallowed reports that the holder's policy
	// disables an encryption the issuer requires.
	ErrCredentialEncryptionDisallowed = common.NewCodedError("credential_encryption_disallowed", "the credential issuer requires a credential encryption this wallet disabled")
)

// Authorization response conditions (RFC 6749 Section 4.1.2, RFC 9207). An
// error redirect is reported as *AuthorizationResponseError instead.
var (
	// ErrAuthorizationRedirectInvalid reports a redirect that is not a URL.
	ErrAuthorizationRedirectInvalid = common.NewCodedError("authorization_redirect_invalid", "authorization redirect could not be read")
	// ErrAuthorizationRedirectURIMismatch reports a redirect to another target
	// than the registered redirect_uri (scheme, host and path).
	ErrAuthorizationRedirectURIMismatch = common.NewCodedError("authorization_redirect_uri_mismatch", "authorization redirect does not match the registered redirect_uri")
	// ErrAuthorizationStateMismatch reports a redirect that does not echo the
	// request's state.
	ErrAuthorizationStateMismatch = common.NewCodedError("authorization_state_mismatch", "authorization redirect state does not match the authorization request")
	// ErrAuthorizationIssMismatch reports an iss that does not identify the
	// authorization server (RFC 9207 Section 2.4).
	ErrAuthorizationIssMismatch = common.NewCodedError("authorization_iss_mismatch", "authorization redirect iss does not identify the authorization server")
	// ErrAuthorizationIssMissing reports a missing iss the server advertises
	// or HAIP requires.
	ErrAuthorizationIssMissing = common.NewCodedError("authorization_iss_missing", "authorization redirect is missing the required iss parameter")
	// ErrAuthorizationCodeMissing reports a redirect with neither a code nor
	// an error.
	ErrAuthorizationCodeMissing = common.NewCodedError("authorization_code_missing", "authorization redirect carries no authorization code")
)

// Notification conditions, reported before a Notification Request is sent
// (OpenID4VCI 1.0 Section 11.1, Draft 13 Section 10.1).
var (
	ErrNotificationIDMissing = common.NewCodedError("notification_id_missing", "notification_id is required")
	// ErrNotificationEventInvalid reports an event other than the three
	// NotificationEvent values.
	ErrNotificationEventInvalid = common.NewCodedError("notification_event_invalid", "notification event is not credential_accepted, credential_failure or credential_deleted")
	// ErrNotificationEventDescriptionInvalid reports a character outside
	// %x20-21 / %x23-5B / %x5D-7E.
	ErrNotificationEventDescriptionInvalid = common.NewCodedError("notification_event_description_invalid", "event_description contains a character the notification request does not allow")
	ErrNotificationAccessTokenMissing      = common.NewCodedError("notification_access_token_missing", "access token is required for the notification request")
	// ErrNotificationEndpointMissing reports an issuer without a
	// notification_endpoint.
	ErrNotificationEndpointMissing = common.NewCodedError("notification_endpoint_missing", "notification endpoint is missing on credential issuer")
	// ErrNotificationDPoPKeyMissing reports a DPoP-bound token without
	// Config.DPoP.Key.
	ErrNotificationDPoPKeyMissing = common.NewCodedError("notification_dpop_key_missing", "the access token is DPoP-bound but no DPoP key is configured")
)

// Draft 13 conditions.
var (
	// ErrDraft13OfferMissing reports a Draft 13 issuance without a Credential
	// Offer (Draft 13 Section 4.1).
	ErrDraft13OfferMissing                  = common.NewCodedError("draft13_offer_missing", "credential offer is required")
	ErrDraft13AuthorizationCodeGrantMissing = common.NewCodedError("draft13_authorization_code_grant_missing", "authorization_code grant is not included in the offer")
	ErrDraft13PreAuthorizedCodeGrantMissing = common.NewCodedError("draft13_pre_authorized_code_grant_missing", "pre-authorized_code grant is not included in the offer")
	ErrDraft13AuthorizationEndpointMissing  = common.NewCodedError("draft13_authorization_endpoint_missing", "authorization endpoint is missing on authorization server")
	ErrDraft13TokenEndpointMissing          = common.NewCodedError("draft13_token_endpoint_missing", "token endpoint is missing on authorization server")
	ErrDraft13CredentialEndpointMissing     = common.NewCodedError("draft13_credential_endpoint_missing", "credential endpoint is missing on credential issuer")
	ErrDraft13DeferredEndpointMissing       = common.NewCodedError("draft13_deferred_endpoint_missing", "deferred credential endpoint is missing on credential issuer")
	ErrDraft13NotificationEndpointMissing   = common.NewCodedError("draft13_notification_endpoint_missing", "notification endpoint is missing on credential issuer")
	// ErrDraft13HolderKeyMissing reports a Credential Request that needs a key
	// proof and has no holder key.
	ErrDraft13HolderKeyMissing = common.NewCodedError("draft13_holder_key_missing", "holder key is required to build the credential request proof")
	// ErrDraft13CredentialConfigurationUnknown reports a configuration the
	// offer or the issuer metadata does not list.
	ErrDraft13CredentialConfigurationUnknown = common.NewCodedError("draft13_credential_configuration_unknown", "credential configuration is not described by the credential issuer metadata")
	// ErrDraft13CredentialResponseInvalid reports a Credential Response with
	// neither a credential nor a transaction_id.
	ErrDraft13CredentialResponseInvalid = common.NewCodedError("draft13_credential_response_invalid", "credential response does not carry a usable credential")
	// ErrDraft13ProofTransformFailed reports that TestHooks.KeyProof refused
	// the key proof.
	ErrDraft13ProofTransformFailed = common.NewCodedError("draft13_proof_transform_failed", "proof transform failed")
)

// invalidArgument wraps ErrInvalidArgument for input rejected before any I/O.
func invalidArgument(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalidArgument}, args...)...)
}

// invalidMetadata wraps receiverTypes.ErrInvalidMetadata for issuer or
// authorization server metadata the issuance cannot use.
func invalidMetadata(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{receiverTypes.ErrInvalidMetadata}, args...)...)
}

// withCode wraps err with sentinel unless err already has a code or is a
// context or network error, which classify codes on its own.
func withCode(sentinel, err error) error {
	if _, coded := common.CodeOf(err); coded || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || isNetworkError(err) {
		return err
	}
	return fmt.Errorf("%w: %w", sentinel, err)
}

// messageError reports msg and unwraps to err, so a code can be added to an
// error whose text callers of an upstream method compare.
type messageError struct {
	msg string
	err error
}

func (e *messageError) Error() string { return e.msg }
func (e *messageError) Unwrap() error { return e.err }

// keepMessage wraps err with sentinel without changing its text.
func keepMessage(sentinel, err error) error {
	if err == nil {
		return nil
	}
	return &messageError{msg: err.Error(), err: fmt.Errorf("%w: %w", sentinel, err)}
}

// classifyKeepingMessage is classify for an upstream method: the returned
// error has a code and err's text.
func classifyKeepingMessage(err error) error {
	classified := classify(err)
	if classified == nil || classified == err {
		return classified
	}
	return &messageError{msg: err.Error(), err: classified}
}
