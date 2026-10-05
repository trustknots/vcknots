package wallet

import (
	"context"
	"fmt"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/acceptance"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/profile"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// CredentialAcceptanceRequest is one credential for
// VerifyCredentialForAcceptance and the issuance context its check needs.
type CredentialAcceptanceRequest struct {
	// Raw is the credential as the Credential Response carried it.
	Raw []byte
	// Flavor is its serialization. Empty infers SD-JWT VC from a "~"
	// separator and JWT VC otherwise.
	Flavor credential.SupportedSerializationFlavor
	// HolderKey is compared with the credential's cnf.jwk.
	HolderKey *jose.JSONWebKey
	// CredentialIssuer is the Credential Issuer Identifier of the issuance the
	// credential came from. A DID issuer is bound to its origin
	// (acceptance.Options.CredentialIssuer).
	CredentialIssuer string
	// Version is the OpenID4VCI version the credential was issued under. The
	// zero value, profile.VersionFinal, applies the wallet's 1.0 profile;
	// profile.VersionDraft13 applies profile.Draft13, which admits the SD-JWT
	// VC typ vc+sd-jwt, and needs Config.Profiles to enable it.
	Version profile.Version
	// Acceptance overrides Config.CredentialAcceptance for this credential.
	Acceptance *acceptance.Policy
	// CredentialConfiguration is the Credential Configuration the credential
	// was issued under, as the issuer metadata describes it. When it lists
	// cryptographic_binding_methods_supported the credential must carry a
	// cnf.jwk that HolderKey matches (OpenID4VCI 1.0 Section 12.2.4, and HAIP
	// 1.0 Section 6.1: the jwk member "MUST" be included "if the corresponding
	// Credential Configuration requires cryptographic holder binding"),
	// whatever the policy's RequireHolderBinding says, as RequestCredential
	// requires. Nil applies the policy as it is.
	CredentialConfiguration *receiverTypes.CredentialConfiguration
}

// VerifyCredentialForAcceptance runs the check issuance runs before storing a
// credential, under req.Acceptance or else Config.CredentialAcceptance, and
// stores nothing. It is the second step for a caller that receives a
// credential on a storeless wallet and persists it later, or that re-checks a
// credential it holds. With no policy it fails with
// ErrCredentialAcceptancePolicyRequired; other failures wrap the acceptance
// package sentinels.
func (w *Wallet) VerifyCredentialForAcceptance(ctx context.Context, req CredentialAcceptanceRequest) (*credential.Credential, *acceptance.Verification, error) {
	parsed, verification, err := w.verifyCredentialForAcceptanceRequest(ctx, req)
	return parsed, verification, classify(err)
}

func (w *Wallet) verifyCredentialForAcceptanceRequest(ctx context.Context, req CredentialAcceptanceRequest) (*credential.Credential, *acceptance.Verification, error) {
	issuanceProfile := w.profile
	switch req.Version {
	case profile.VersionFinal:
	case profile.VersionDraft13:
		if err := w.requireDraft13(); err != nil {
			return nil, nil, err
		}
		issuanceProfile = profile.Draft13()
	default:
		return nil, nil, invalidArgument("%s is not an OpenID4VCI version", req.Version)
	}
	policy, err := w.acceptancePolicy(req.Acceptance)
	if err != nil {
		return nil, nil, err
	}
	if req.CredentialConfiguration != nil && configurationRequiresBinding(*req.CredentialConfiguration) && !policy.RequireHolderBinding {
		bound := *policy
		bound.RequireHolderBinding = true
		policy = &bound
	}
	return w.verifyCredentialUnder(ctx, issuanceProfile, policy, req.Raw, req.Flavor, req.HolderKey, req.CredentialIssuer)
}

// acceptancePolicy returns the policy a credential is accepted under: the
// per-request override, or else Config.CredentialAcceptance. Neither fails
// with ErrCredentialAcceptancePolicyRequired: no credential is returned or
// stored without an authenticated issuer (SD-JWT VC -19 §2.4, §2.5).
func (w *Wallet) acceptancePolicy(override *acceptance.Policy) (*acceptance.Policy, error) {
	if override != nil {
		return override, nil
	}
	if w.credentialAcceptance != nil {
		return w.credentialAcceptance, nil
	}
	return nil, fmt.Errorf("issuer verification is not configured: %w", ErrCredentialAcceptancePolicyRequired)
}

// stateAcceptancePolicy is acceptancePolicy for an issuance state. An
// issuance begun or requested with its own policy records that in the state's
// AcceptanceOverridden, which survives serialization while the policy does
// not; such a state without its policy fails with
// ErrCredentialAcceptancePolicyRequired rather than silently falling back to
// Config.CredentialAcceptance. field names what the caller sets again.
func (w *Wallet) stateAcceptancePolicy(overridden bool, policy *acceptance.Policy, field string) (*acceptance.Policy, error) {
	if overridden && policy == nil {
		return nil, fmt.Errorf("the issuance state records its own acceptance policy, which is not serialized; set %s again: %w", field, ErrCredentialAcceptancePolicyRequired)
	}
	return w.acceptancePolicy(policy)
}

// authorizationAcceptancePolicy is stateAcceptancePolicy for
// AuthorizeIssuance.
func (w *Wallet) authorizationAcceptancePolicy(a *IssuanceAuthorization) (*acceptance.Policy, error) {
	return w.stateAcceptancePolicy(a.AcceptanceOverridden, a.Acceptance, "IssuanceAuthorization.Acceptance")
}

// grantAcceptancePolicy is the policy a Credential Request accepts its
// credentials under: override (CredentialRequest.Acceptance), else the
// policy the grant carries from the start of the flow, else
// Config.CredentialAcceptance. perRequest is the policy a Deferred issuance
// carries on, nil when Config.CredentialAcceptance applies.
func (w *Wallet) grantAcceptancePolicy(grant *IssuanceGrant, override *acceptance.Policy) (policy, perRequest *acceptance.Policy, err error) {
	if override != nil {
		return override, override, nil
	}
	policy, err = w.stateAcceptancePolicy(grant.AcceptanceOverridden, grant.Acceptance, "IssuanceGrant.Acceptance or CredentialRequest.Acceptance")
	if err != nil {
		return nil, nil, err
	}
	return policy, grant.Acceptance, nil
}

// deferredAcceptancePolicy is stateAcceptancePolicy for a deferred issuance.
func (w *Wallet) deferredAcceptancePolicy(d *DeferredIssuance) (*acceptance.Policy, error) {
	return w.stateAcceptancePolicy(d.AcceptanceOverridden, d.Acceptance, "DeferredIssuance.Acceptance")
}

// verifyCredentialUnder applies policy to raw under issuance profile p: the
// wallet's 1.0 profile for OpenID4VCI 1.0, and profile.Draft13 for a Draft 13
// credential. credentialIssuer is the Credential Issuer Identifier of the
// issuance.
func (w *Wallet) verifyCredentialUnder(ctx context.Context, p profile.Profile, policy *acceptance.Policy, raw []byte, flavor credential.SupportedSerializationFlavor, holderKey *jose.JSONWebKey, credentialIssuer string) (*credential.Credential, *acceptance.Verification, error) {
	if policy == nil {
		return nil, nil, fmt.Errorf("issuer verification is not configured: %w", ErrCredentialAcceptancePolicyRequired)
	}
	acceptor, err := acceptance.NewAcceptor(p, w.serializer, w.verifier)
	if err != nil {
		return nil, nil, err
	}
	opts := acceptance.Options{Flavor: flavor, HolderKey: holderKey, CredentialIssuer: credentialIssuer}
	return acceptor.Verify(ctx, raw, *policy, opts)
}
