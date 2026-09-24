package wallet

import (
	"context"
	"fmt"
	"slices"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/attestation"
	"github.com/trustknots/vcknots/wallet/internal/jwtproof"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// attestationPolicyFor is the policy an attestation from provider is
// validated under: Config.Attestation.Trust, with RequireX5C raised under HAIP
// (HAIP Sections 4.4.1 and 4.5.1), and, when no resolver is configured, the
// bundled static attester's own public key for an attestation without x5c.
func (w *Wallet) attestationPolicyFor(provider any) attestation.TrustPolicy {
	policy := w.attestationSettings().Trust
	if w.profile.IsHAIP() {
		policy.RequireX5C = true
	}
	if policy.ResolveKey != nil {
		return policy
	}
	var key interface{ PublicKey() jose.JSONWebKey }
	switch attester := provider.(type) {
	case *attestation.StaticClientAttester:
		if attester != nil && attester.Key != nil {
			key = attester.Key
		}
	case *attestation.StaticKeyAttester:
		if attester != nil && attester.Key != nil {
			key = attester.Key
		}
	}
	if key != nil {
		public := key.PublicKey()
		policy.ResolveKey = func(attestation.JOSEHeader) (any, error) { return public.Key, nil }
	}
	return policy
}

// clientAttestationKey is the wallet instance key a Client Attestation binds:
// Config.Attestation.ClientKey, else Config.DPoP.Key.
func (w *Wallet) clientAttestationKey() IKeyEntry {
	if w.attestationSettings().ClientKey != nil {
		return w.attestationSettings().ClientKey
	}
	return w.dpop.Key
}

// clientAttestationFactory obtains and authenticates the Client Attestation
// for the authorization server asIssuer (OpenID4VCI 1.0 Appendix E) and
// returns the header factory, which signs a fresh PoP for every attempt. It
// returns nil when no Config.Attestation.Client is configured.
func (w *Wallet) clientAttestationFactory(
	ctx context.Context,
	transport receiverTypes.AuthorizationTransport,
	asMetadata *receiverTypes.AuthorizationServerMetadata,
	asIssuer string,
) (receiverTypes.OAuthClientAttestationHeadersFactory, error) {
	provider := w.attestationSettings().Client
	if provider == nil {
		return nil, nil
	}
	key := w.clientAttestationKey()
	if key == nil {
		return nil, invalidArgument("a client attestation needs Config.Attestation.ClientKey or Config.DPoP.Key")
	}
	clientID := w.clientAuth.ClientID
	if clientID == "" {
		return nil, invalidArgument("a client attestation needs Config.ClientAuth.ClientID")
	}
	clientKey := key.PublicKey()
	request := attestation.ClientRequest{
		ClientID:            clientID,
		ClientKey:           clientKey.Public(),
		AuthorizationServer: asIssuer,
	}
	// HAIP Section 4.4.1: authenticate the attestation before any request
	// carries it.
	clientAttestation, err := provider.ClientAttestation(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain client attestation: %w", withCode(attestation.ErrClientAttestationInvalid, err))
	}
	if err := attestation.ValidateClientAttestation(ctx, clientAttestation, request, w.attestationPolicyFor(provider)); err != nil {
		return nil, err
	}
	challenge := ""
	if asMetadata.ChallengeEndpoint != nil {
		response, err := transport.FetchClientAttestationChallenge(ctx, *asMetadata.ChallengeEndpoint)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch client attestation challenge: %w", err)
		}
		challenge = response.AttestationChallenge
	}
	return func() (receiverTypes.OAuthClientAttestationHeaders, error) {
		pop, err := jwtproof.ClientAttestationPoP(ctx, key, jwtproof.ClientAttestationPoPOptions{
			ClientID:  clientID,
			Audience:  asIssuer,
			Challenge: challenge,
			Lifetime:  clientAttestationPoPLifetime,
		})
		if err != nil {
			return receiverTypes.OAuthClientAttestationHeaders{}, err
		}
		return receiverTypes.OAuthClientAttestationHeaders{ClientAttestation: clientAttestation.JWT, ClientAttestationPop: pop}, nil
	}, nil
}

// keyAttestationFor returns the key attestation for holderKeys and cNonce:
// supplied when set, else one from Config.Attestation.Key, authenticated and
// with an alg listed in signingAlgValues (Appendix F.1).
func (w *Wallet) keyAttestationFor(
	ctx context.Context,
	supplied *attestation.KeyAttestation,
	request attestation.KeyRequest,
	signingAlgValues []jose.SignatureAlgorithm,
) (string, error) {
	keyAttestation := supplied
	if keyAttestation == nil {
		if w.attestationSettings().Key == nil {
			return "", ErrKeyAttestationRequired
		}
		provided, err := w.attestationSettings().Key.KeyAttestation(ctx, request)
		if err != nil {
			return "", fmt.Errorf("failed to obtain key attestation: %w", withCode(attestation.ErrKeyAttestationInvalid, err))
		}
		keyAttestation = provided
	}
	if err := attestation.ValidateKeyAttestation(ctx, keyAttestation, request, w.attestationPolicyFor(w.attestationSettings().Key)); err != nil {
		return "", err
	}
	if len(signingAlgValues) > 0 {
		header, err := jwsHeader(keyAttestation.JWT)
		if err != nil {
			return "", fmt.Errorf("key attestation is malformed: %w: %w", attestation.ErrKeyAttestationInvalid, err)
		}
		alg, _ := header["alg"].(string)
		if !slices.Contains(signingAlgValues, jose.SignatureAlgorithm(alg)) {
			return "", fmt.Errorf("key attestation is signed with %q, not one of proof_signing_alg_values_supported %v: %w", alg, signingAlgValues, ErrProofAlgorithmNotSupported)
		}
	}
	return keyAttestation.JWT, nil
}

// issuerRequiresKeyAttestation reports whether the configuration lists
// proof_types_supported.jwt.key_attestations_required (Appendix D); presence,
// even empty, is the signal.
func issuerRequiresKeyAttestation(config receiverTypes.CredentialConfiguration) bool {
	if config.ProofTypesSupported == nil {
		return false
	}
	jwtProof, ok := (*config.ProofTypesSupported)["jwt"]
	return ok && jwtProof.KeyAttestationsRequired != nil
}
