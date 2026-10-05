package issuerkeys

import (
	"bytes"
	"crypto"

	"github.com/go-jose/go-jose/v4"
)

// This file holds the helpers the resolver's callers share: the credential
// acceptor (wallet/acceptance) calls Resolve itself, and the Token Status List
// checker's key hook (statuslist.Checker.ResolveIssuerKeys) is adapted in
// statuslistkeys.go.

// CandidateFor returns the candidate whose key is key, compared by RFC 7638
// JWK thumbprint, so members that carry no key material (`kid`, `alg`, `use`)
// do not matter. When the same key was produced by several rungs, the first in
// ladder order is returned, which is the one a caller that tried the keys in
// order verified with.
func (res *Resolution) CandidateFor(key jose.JSONWebKey) (Candidate, bool) {
	if res == nil {
		return Candidate{}, false
	}
	wanted, ok := keyThumbprint(key)
	if !ok {
		return Candidate{}, false
	}
	for _, candidate := range res.Candidates {
		if thumbprint, ok := keyThumbprint(candidate.Key); ok && bytes.Equal(thumbprint, wanted) {
			return candidate, true
		}
	}
	return Candidate{}, false
}

// failureChainUntrusted is the `x5c` rung Failure recorded when a chain does
// not reach a configured trust anchor, or does not name the issuer's host.
const failureChainUntrusted = "certificate chain is not trusted"

// issuerCandidates returns the candidates attributable to issuer, the JWT
// `iss`: those whose Candidate.Issuer equals it.
func issuerCandidates(candidates []Candidate, issuer string) []Candidate {
	narrowed := make([]Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Issuer == issuer {
			narrowed = append(narrowed, candidate)
		}
	}
	return narrowed
}

// requestFromHeader fills template with what a JWT's `iss` and protected header
// say about its signer.
func requestFromHeader(template Request, issuer string, header map[string]any) Request {
	request := template
	request.Issuer = issuer
	request.KeyID, _ = header["kid"].(string)
	request.Algorithm, _ = header["alg"].(string)
	request.X5C = headerX5C(header["x5c"])
	return request
}

// headerX5C reads an `x5c` header member as decoded into a map[string]any (a
// []any of strings) or into a typed header (a []string). Any other shape, or an
// entry that is not a string, yields nothing: the ladder treats a malformed
// chain as an absent one.
func headerX5C(raw any) []string {
	switch values := raw.(type) {
	case []string:
		return values
	case []any:
		chain := make([]string, 0, len(values))
		for _, value := range values {
			entry, ok := value.(string)
			if !ok {
				return nil
			}
			chain = append(chain, entry)
		}
		return chain
	default:
		return nil
	}
}

// candidateKeys returns the signature keys of candidates in order, each reduced
// to its public half.
func candidateKeys(candidates []Candidate) []jose.JSONWebKey {
	keys := make([]jose.JSONWebKey, 0, len(candidates))
	for _, candidate := range candidates {
		if key, ok := publicKey(candidate.Key); ok && isSignatureKey(key) {
			keys = append(keys, key)
		}
	}
	return keys
}

// keyThumbprint returns the RFC 7638 SHA-256 thumbprint of key's public half.
func keyThumbprint(key jose.JSONWebKey) ([]byte, bool) {
	public, ok := publicKey(key)
	if !ok {
		return nil, false
	}
	thumbprint, err := public.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, false
	}
	return thumbprint, true
}
