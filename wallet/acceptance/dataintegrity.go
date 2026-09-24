package acceptance

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/trustknots/vcknots/wallet/credential"
	"github.com/trustknots/vcknots/wallet/credential/dataintegrity"
)

// runDataIntegrity is run for an ldp_vc: a W3C VC secured with an embedded
// eddsa-rdfc-2022 Data Integrity proof. A nil policy means Parse.
func (a *Acceptor) runDataIntegrity(raw []byte, opts Options, policy *Policy) (*credential.Credential, *Verification, error) {
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil || document == nil {
		return nil, nil, fmt.Errorf("%w: a Data Integrity credential must be a JSON object", ErrCredentialParse)
	}
	parsed, err := a.serializer.DeserializeCredential(credential.LdpVc, raw)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrCredentialParse, err)
	}
	verification := &Verification{}
	requireBinding := policy != nil && policy.RequireHolderBinding
	if err := checkHolderBinding(document, opts.HolderKey, requireBinding, verification); err != nil {
		return nil, nil, err
	}
	if policy == nil {
		return parsed, verification, nil
	}
	now := time.Now()
	if policy.Now != nil {
		now = policy.Now()
	}
	if err := authenticateDataIntegrityIssuer(document, parsed.Issuer, policy, now, verification); err != nil {
		return nil, nil, err
	}
	if period := parsed.ValidPeriod; period != nil {
		if period.To != nil && !period.To.After(now.Add(-policy.ClockSkew)) {
			return nil, nil, ErrCredentialExpired
		}
		if period.From != nil && period.From.After(now.Add(policy.ClockSkew)) {
			return nil, nil, ErrCredentialNotYetValid
		}
	}
	return parsed, verification, nil
}

// authenticateDataIntegrityIssuer verifies the issuer's assertionMethod proof
// under a key the policy's resolver returns. The resolver receives the
// proof's verificationMethod as the kid and "EdDSA" as the alg of header. The
// verificationMethod must be a fragment of the issuer identifier, so a key
// another party controls cannot sign for the issuer. An ldp_vc has no x5c, so
// IssuerX509 alone authenticates nothing.
func authenticateDataIntegrityIssuer(document map[string]any, issuer string, policy *Policy, now time.Time, verification *Verification) error {
	if !policy.resolvesIssuerKeys() {
		if policy.IssuerX509 == nil && policy.UnverifiedIssuer {
			return nil
		}
		return fmt.Errorf("%w: a Data Integrity credential needs an issuer key resolver", ErrIssuerKeyUnresolved)
	}
	method, err := dataIntegrityVerificationMethod(document["proof"])
	if err != nil {
		return err
	}
	controller, _, _ := strings.Cut(method, "#")
	if issuer == "" || controller != issuer {
		return fmt.Errorf("%w: verificationMethod %q is not controlled by issuer %q", ErrIssuerSignatureInvalid, method, issuer)
	}
	header := map[string]any{"alg": string(jose.EdDSA), "kid": method}
	keys, err := resolveIssuerKeyCandidates(policy, issuer, header, document)
	if err != nil {
		return err
	}
	options := dataintegrity.VerifyOptions{
		ProofPurpose:       dataintegrity.ProofPurposeAssertionMethod,
		VerificationMethod: method,
		Now:                now,
		ClockSkew:          policy.ClockSkew,
	}
	var lastErr error
	for i := range keys {
		publicKey, ok := keys[i].Key.(ed25519.PublicKey)
		if !ok {
			continue
		}
		if lastErr = dataintegrity.VerifyEddsaRdfc2022WithOptions(document, policy.DataIntegrityContexts, publicKey, options); lastErr != nil {
			continue
		}
		verification.IssuerKeyID = method
		verified := keys[i].Public()
		verification.IssuerKey = &verified
		return nil
	}
	if lastErr != nil {
		return fmt.Errorf("%w: %w", ErrIssuerSignatureInvalid, lastErr)
	}
	return fmt.Errorf("%w: no resolved issuer key is an Ed25519 key", ErrIssuerSignatureInvalid)
}

// dataIntegrityVerificationMethod returns the verificationMethod of the one
// eddsa-rdfc-2022 DataIntegrityProof in a proof object or proof set.
func dataIntegrityVerificationMethod(member any) (string, error) {
	proofs, ok := member.([]any)
	if !ok {
		proofs = []any{member}
	}
	method := ""
	for _, entry := range proofs {
		proof, _ := entry.(map[string]any)
		if proof["type"] != dataintegrity.ProofType || proof["cryptosuite"] != dataintegrity.CryptosuiteEddsaRdfc2022 {
			continue
		}
		if method != "" {
			return "", fmt.Errorf("%w: the credential carries several %s proofs", ErrIssuerSignatureInvalid, dataintegrity.CryptosuiteEddsaRdfc2022)
		}
		if method, _ = proof["verificationMethod"].(string); method == "" {
			return "", fmt.Errorf("%w: the proof has no verificationMethod", ErrIssuerSignatureInvalid)
		}
	}
	if method == "" {
		return "", fmt.Errorf("%w: the credential carries no %s DataIntegrityProof", ErrIssuerSignatureInvalid, dataintegrity.CryptosuiteEddsaRdfc2022)
	}
	return method, nil
}
