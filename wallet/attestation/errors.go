package attestation

import "github.com/trustknots/vcknots/wallet/common"

// Sentinel errors of the validators. The wrapped error names the check that
// failed.
var (
	// ErrClientAttestationInvalid reports a Wallet Attestation that is empty,
	// malformed, unauthenticated, or not bound to this client_id, client key,
	// authorization server or a future exp.
	ErrClientAttestationInvalid = common.NewCodedError("client_attestation_invalid", "client attestation is not valid for this wallet instance")
	// ErrKeyAttestationInvalid reports a key attestation that is empty,
	// malformed, unauthenticated, or does not cover the holder keys, c_nonce,
	// audience or a future exp of the Credential Request.
	ErrKeyAttestationInvalid = common.NewCodedError("key_attestation_invalid", "key attestation is not valid for this credential request")
)
