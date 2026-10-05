package wallet

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"slices"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/trustknots/vcknots/wallet/attestation"
	"github.com/trustknots/vcknots/wallet/internal/jwtproof"
	"github.com/trustknots/vcknots/wallet/keystore"
	receiverTypes "github.com/trustknots/vcknots/wallet/receiver/types"
)

// attestationPolicyFor is the policy an attestation from provider is
// validated under: Config.Attestation.Trust, with the profile's
// Options.AttestationX5C added to its X5C rules (HAIP Sections 4.4.1 and
// 4.5.1), and, when no resolver is configured, the bundled static attester's
// own public key for an attestation without x5c.
func (w *Wallet) attestationPolicyFor(provider any) attestation.TrustPolicy {
	policy := w.attestationSettings().Trust
	policy.X5C = policy.X5C.Union(w.options().AttestationX5C)
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

// clientInstanceKey returns the Client Instance Key a Client Attestation of
// one flow binds, and, when the wallet generated it, its private JWK for the
// flow's state. recorded is the key a previous stage of the flow kept.
//
//   - Config.Attestation.ClientKey is used as configured.
//   - Config.Attestation.ClientKeyFromDPoP uses Config.DPoP.Key.
//   - Otherwise the flow gets its own ephemeral key, so no two authorization
//     servers see the same key
//     (draft-ietf-oauth-attestation-based-client-auth Section 11.1
//     RECOMMENDED).
func (w *Wallet) clientInstanceKey(recorded *jose.JSONWebKey) (IKeyEntry, *jose.JSONWebKey, error) {
	settings := w.attestationSettings()
	switch {
	case settings.ClientKey != nil && settings.ClientKeyFromDPoP:
		return nil, nil, invalidArgument("Config.Attestation.ClientKey and ClientKeyFromDPoP are exclusive")
	case settings.ClientKey != nil:
		return settings.ClientKey, nil, nil
	case settings.ClientKeyFromDPoP:
		if w.dpop.Key == nil {
			return nil, nil, invalidArgument("Config.Attestation.ClientKeyFromDPoP needs Config.DPoP.Key")
		}
		return w.dpop.Key, nil, nil
	case recorded != nil:
		key, err := keystore.NewKeyEntryFromJWK(*recorded)
		if err != nil {
			return nil, nil, fmt.Errorf("the state's client instance key: %w: %w", ErrIssuanceStateMismatch, err)
		}
		return key, nil, nil
	}
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate a client instance key: %w", err)
	}
	jwk := jose.JSONWebKey{Key: private, KeyID: uuid.NewString(), Algorithm: string(jose.ES256), Use: "sig"}
	key, err := keystore.NewKeyEntryFromJWK(jwk)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate a client instance key: %w", err)
	}
	return key, &jwk, nil
}

// clientAttestationFactory obtains and authenticates the Client Attestation
// for the authorization server asIssuer (OpenID4VCI 1.0 Appendix E) and
// returns the prover for the Client Instance Key key, which signs a fresh PoP
// for every attempt carrying the
// Challenge the receiver hands it. It fetches a Challenge from the
// challenge_endpoint when the server advertises one, which is then the most
// recently received Challenge (draft-ietf-oauth-attestation-based-client-auth-07
// Section 8, -11 Section 6). It returns the zero prover when no
// Config.Attestation.Client is configured.
func (w *Wallet) clientAttestationFactory(
	ctx context.Context,
	transport receiverTypes.AuthorizationTransport,
	asMetadata *receiverTypes.AuthorizationServerMetadata,
	asIssuer string,
	key IKeyEntry,
) (receiverTypes.ClientAttestationProver, error) {
	provider := w.attestationSettings().Client
	if provider == nil {
		return receiverTypes.ClientAttestationProver{}, nil
	}
	if key == nil {
		return receiverTypes.ClientAttestationProver{}, invalidArgument("a client attestation needs a Client Instance Key")
	}
	clientID := w.clientAuth.ClientID
	if clientID == "" {
		return receiverTypes.ClientAttestationProver{}, invalidArgument("a client attestation needs Config.ClientAuth.ClientID")
	}
	clientKey := key.PublicKey()
	thumbprint, err := jwkThumbprint(clientKey)
	if err != nil {
		return receiverTypes.ClientAttestationProver{}, fmt.Errorf("client instance key: %w", err)
	}
	request := attestation.ClientRequest{
		ClientID:            clientID,
		ClientKey:           clientKey.Public(),
		AuthorizationServer: asIssuer,
	}
	// HAIP Section 4.4.1: authenticate the attestation before any request
	// carries it.
	clientAttestation, err := provider.ClientAttestation(ctx, request)
	if err != nil {
		return receiverTypes.ClientAttestationProver{}, fmt.Errorf("failed to obtain client attestation: %w", withCode(attestation.ErrClientAttestationInvalid, err))
	}
	if err := attestation.ValidateClientAttestation(ctx, clientAttestation, request, w.attestationPolicyFor(provider)); err != nil {
		return receiverTypes.ClientAttestationProver{}, err
	}
	challenge := ""
	if asMetadata.ChallengeEndpoint != nil {
		response, err := transport.FetchClientAttestationChallenge(ctx, *asMetadata.ChallengeEndpoint)
		if err != nil {
			return receiverTypes.ClientAttestationProver{}, fmt.Errorf("failed to fetch client attestation challenge: %w", err)
		}
		challenge = response.AttestationChallenge
	}
	return receiverTypes.ClientAttestationProver{
		KeyThumbprint: thumbprint,
		Challenge:     challenge,
		Headers: func(challenge string) (receiverTypes.OAuthClientAttestationHeaders, error) {
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
		},
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
