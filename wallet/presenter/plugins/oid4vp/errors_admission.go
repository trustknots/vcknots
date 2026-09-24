package oid4vp

import "github.com/trustknots/vcknots/wallet/common"

// Admission sentinels. Each names one condition under which the Wallet refuses
// an Authorization Request while parsing it, so an integrator that renders the
// refusal to a person, or answers the Verifier with its own error vocabulary,
// branches on the condition with errors.Is or common.CodeOf instead of on
// message text. They are wrapped inside an *AuthorizationRequestError where the
// refusal is also an OAuth error the Verifier may be told about.
var (
	// ErrNonceRequired reports that the Authorization Request carries no
	// nonce. OpenID4VP 1.0 Section 5.2 makes nonce REQUIRED, and a
	// presentation bound to no nonce could be replayed to the Verifier.
	ErrNonceRequired = common.NewCodedError("nonce_required", "authorization request nonce is required")
	// ErrRequestObjectWalletNonceMismatch reports that a Request Object
	// fetched with a request_uri POST does not echo the wallet_nonce the
	// Wallet sent. OpenID4VP 1.0 Section 5.10.1: "If it does not, the Wallet
	// MUST terminate request processing."
	ErrRequestObjectWalletNonceMismatch = common.NewCodedError("request_object_wallet_nonce_mismatch", "request object wallet_nonce does not match the one the wallet sent")
	// ErrTransactionDataTypeUnsupported reports a transaction_data entry whose
	// type this Wallet does not support. OpenID4VP 1.0 Section 5.1: "If the
	// Wallet does not support this transaction data type, it SHOULD reject the
	// request."
	ErrTransactionDataTypeUnsupported = common.NewCodedError("transaction_data_type_unsupported", "transaction_data type is not supported by this wallet")
	// ErrResponseURIClientIDMismatch reports a redirect_uri Client Identifier
	// whose Response URI is not the one the Client Identifier names. OpenID4VP
	// 1.0 Section 5.9.3 (and Draft24 Section 5.10.1): the original Client
	// Identifier "is the Verifier's Redirect URI (or Response URI when
	// Response Mode direct_post is used)".
	ErrResponseURIClientIDMismatch = common.NewCodedError("response_uri_client_id_mismatch", "response_uri does not match the redirect_uri Client Identifier")
	// ErrResponseEncryptionKeyMissing reports a direct_post.jwt or dc_api.jwt
	// request whose Verifier metadata carries no jwks to encrypt the
	// Authorization Response to (OpenID4VP 1.0 Section 8.3).
	ErrResponseEncryptionKeyMissing = common.NewCodedError("response_encryption_jwks_missing", "response encryption requires verifier encryption keys in client_metadata.jwks")
	// ErrResponseEncryptionKeyUnusable reports an encrypted-response request whose
	// Verifier metadata jwks holds no key this Wallet can encrypt to under the
	// active profile (OpenID4VP 1.0 Section 8.3, HAIP Section 5).
	ErrResponseEncryptionKeyUnusable = common.NewCodedError("response_encryption_jwks_invalid", "client_metadata.jwks holds no usable response encryption key")
	// ErrResponseEncryptionEncUnsupported reports that
	// encrypted_response_enc_values_supported offers no content encryption
	// this Wallet supports under the active profile.
	ErrResponseEncryptionEncUnsupported = common.NewCodedError("response_encryption_enc_unsupported", "encrypted_response_enc_values_supported offers no supported content encryption")
	// ErrResponseEncryptionEncMissing reports a HAIP encrypted-response request
	// whose Verifier does not list both A128GCM and A256GCM in
	// encrypted_response_enc_values_supported, which HAIP Section 5 requires
	// of every Verifier using response encryption.
	ErrResponseEncryptionEncMissing = common.NewCodedError("response_encryption_enc_missing", "HAIP requires encrypted_response_enc_values_supported to list A128GCM and A256GCM")
	// ErrClientMetadataJWKKeyIDMissing reports a client_metadata.jwks member
	// without a kid. OpenID4VP 1.0 Section 5.1: "Each JWK in the set MUST have
	// a `kid` (Key ID) parameter". Reported only when the presenter sets
	// RequireClientMetadataJWKKeyIDs.
	ErrClientMetadataJWKKeyIDMissing = common.NewCodedError("client_metadata_jwks_kid_missing", "every key in client_metadata.jwks must have a kid")
	// ErrClientMetadataJWKKeyIDDuplicate reports two client_metadata.jwks
	// members with the same kid, which then does not "uniquely identif[y] the
	// key within the context of the request" (OpenID4VP 1.0 Section 5.1).
	// Reported only when the presenter sets RequireClientMetadataJWKKeyIDs.
	ErrClientMetadataJWKKeyIDDuplicate = common.NewCodedError("client_metadata_jwks_kid_duplicate", "every kid in client_metadata.jwks must be unique")
)
