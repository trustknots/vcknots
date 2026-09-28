package oid4vci

import (
	"net/http"
	"strings"
)

// attestationChallengeHeader is the header an authorization server provides a
// fresh Challenge in, on any response or with a use_attestation_challenge
// error (draft-ietf-oauth-attestation-based-client-auth-07 Section 8.1, -11
// Sections 6.1 and 6.2).
const attestationChallengeHeader = "OAuth-Client-Attestation-Challenge"

// useAttestationChallenge is the error code an authorization server answers
// with when the Client Attestation PoP does not carry the Challenge it expects
// (-07 Section 6.2, -11 Section 7.4).
const useAttestationChallenge = "use_attestation_challenge"

// maxAttestationChallengeServers bounds the (server, key) entries a receiver
// keeps a Challenge for.
const maxAttestationChallengeServers = 32

// attestationChallengeKey identifies the Challenges a Client Attestation PoP
// may carry: the authorization server (scheme and authority) and the Client
// Instance Key. A Challenge is kept per key so that it is never presented with
// another key, which would let the server link the keys.
type attestationChallengeKey struct {
	server        string
	keyThumbprint string
}

// attestationChallengeKey is the key of ex's Challenges; ok is false when ex
// carries no attestation or no key thumbprint.
func (ex exchange) attestationChallengeKey() (attestationChallengeKey, bool) {
	if ex.attestation.Headers == nil || ex.attestation.KeyThumbprint == "" {
		return attestationChallengeKey{}, false
	}
	return attestationChallengeKey{
		server:        strings.ToLower(ex.url.Scheme) + "://" + strings.ToLower(ex.url.Host),
		keyThumbprint: ex.attestation.KeyThumbprint,
	}, true
}

// attestationChallengeFor is the Challenge the first attempt of ex carries:
// the caller's own (from the challenge endpoint), else the latest one a
// response for the same server and key provided, else none.
func (o *Oid4vciReceiver) attestationChallengeFor(ex exchange) string {
	if challenge := strings.TrimSpace(ex.attestation.Challenge); challenge != "" {
		return challenge
	}
	key, ok := ex.attestationChallengeKey()
	if !ok {
		return ""
	}
	o.dpopNonceMu.Lock()
	defer o.dpopNonceMu.Unlock()
	if o.attestationChallenges == nil {
		return ""
	}
	challenge, _ := o.attestationChallenges.get(key)
	return challenge
}

// rememberAttestationChallenge keeps the Challenge a response to ex provided,
// which the next PoP for the same server and key must carry ("The Client MUST
// use this new Challenge for the next OAuth-Client-Attestation-PoP", -07
// Section 8.1).
func (o *Oid4vciReceiver) rememberAttestationChallenge(ex exchange, header http.Header) {
	challenge := strings.TrimSpace(header.Get(attestationChallengeHeader))
	key, ok := ex.attestationChallengeKey()
	if challenge == "" || !ok {
		return
	}
	o.dpopNonceMu.Lock()
	defer o.dpopNonceMu.Unlock()
	if o.attestationChallenges == nil {
		o.attestationChallenges = newRecentValues[attestationChallengeKey](maxAttestationChallengeServers)
	}
	o.attestationChallenges.put(key, challenge)
}

// freshAttestationChallenge returns the Challenge of a use_attestation_challenge
// error when it differs from the one the attempt carried, or "" when the
// response is not such an error or brings nothing new.
func freshAttestationChallenge(response *exchangeResponse, sent string) string {
	if response.statusCode != http.StatusBadRequest || oauthErrorCode(response.body) != useAttestationChallenge {
		return ""
	}
	fresh := strings.TrimSpace(response.header.Get(attestationChallengeHeader))
	if fresh == sent {
		return ""
	}
	return fresh
}
