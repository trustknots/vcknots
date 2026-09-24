// Package oid4vcijwe holds the JWE algorithm allowlist for OpenID4VCI 1.0 §10
// encrypted Credential Requests and Responses, so every encoder and decoder in
// the wallet accepts the same set.
package oid4vcijwe

import "github.com/go-jose/go-jose/v4"

// KeyAlgorithms returns the accepted JWE key management algorithms: the
// RFC 7518 §4.6 ECDH-ES family and §4.3 RSA-OAEP-256. RSA1_5 (RFC 8017 §7.2,
// Bleichenbacher-attackable) and SHA-1 RSA-OAEP are excluded.
func KeyAlgorithms() []jose.KeyAlgorithm {
	return []jose.KeyAlgorithm{jose.ECDH_ES, jose.ECDH_ES_A128KW, jose.ECDH_ES_A192KW, jose.ECDH_ES_A256KW, jose.RSA_OAEP_256}
}

// ContentEncryptions returns the accepted JWE content encryption algorithms.
func ContentEncryptions() []jose.ContentEncryption {
	return []jose.ContentEncryption{jose.A128GCM, jose.A192GCM, jose.A256GCM, jose.A128CBC_HS256, jose.A192CBC_HS384, jose.A256CBC_HS512}
}
