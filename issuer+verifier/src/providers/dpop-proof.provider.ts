import { calculateJwkThumbprint, decodeProtectedHeader, importJWK, jwtVerify } from 'jose'
import { calculateAccessTokenHash } from '../dpop-proof'
import { DPoPProofPayload, DPoPProofVerifyContext, VerifiedDpopProof } from '../dpop-proof.types'
import { raise } from '../errors/vcknots.error'
import type { DPoPProofProvider } from './provider.types'

const DPOP_PROOF_TYP = 'dpop+jwt'
const DEFAULT_DPOP_PROOF_MAX_TOKEN_AGE_SECONDS = 300
const DEFAULT_DPOP_PROOF_CLOCK_TOLERANCE_SECONDS = 60

/**
 * Rejects DPoP proof algorithms that cannot be accepted for proof-of-possession.
 *
 * RFC 9449 requires an asymmetric digital signature algorithm for DPoP proofs.
 * This implementation rejects empty `alg`, `none`, and the JWA HMAC family
 * (`HS*`) before attempting JWK import or JWT signature verification.
 */
function isProhibitedDpopProofAlg(alg: string): boolean {
  const trimmed = alg.trim()
  if (trimmed.length === 0) return true
  if (trimmed.toLowerCase() === 'none') return true
  return /^hs/i.test(trimmed)
}
/**
 * Normalizes `htu` values for RFC 9449 request URI comparison.
 *
 * The DPoP `htu` claim must match the HTTP request URI, while query and
 * fragment components are ignored. Default ports are also normalized so
 * semantically equivalent HTTP(S) URIs compare consistently.
 */
function normalizeHtu(value: string): string {
  let normalized: URL
  try {
    normalized = new URL(value)
  } catch (error) {
    throw raise('invalid_dpop_proof', {
      message: 'DPoP proof JWT htu claim must be a valid absolute URI.',
      cause: error,
    })
  }

  normalized.search = ''
  normalized.hash = ''

  if (
    (normalized.protocol === 'https:' && normalized.port === '443') ||
    (normalized.protocol === 'http:' && normalized.port === '80')
  ) {
    normalized.port = ''
  }

  return normalized.toString()
}

/**
 * Validates required DPoP Proof JWT payload claims with Zod, then maps schema
 * failures back to the provider's domain error messages.
 *
 * Request-specific checks such as `htm` and `htu` comparison intentionally stay
 * in `verifyProof()` because they depend on the actual HTTP request context.
 */
function parseDpopProofPayload(value: unknown): DPoPProofPayload {
  try {
    return DPoPProofPayload(value)
  } catch (error) {
    throw raise('invalid_dpop_proof', {
      message: 'DPoP proof JWT payload claims are invalid.',
      cause: error,
    })
  }
}

export type DPoPProofFactoryOptions = {
  maxTokenAgeSeconds?: number
  clockToleranceSeconds?: number
}

export const dpopProof = (factoryOptions?: DPoPProofFactoryOptions): DPoPProofProvider => {
  const maxTokenAge = factoryOptions?.maxTokenAgeSeconds ?? DEFAULT_DPOP_PROOF_MAX_TOKEN_AGE_SECONDS
  const clockTolerance =
    factoryOptions?.clockToleranceSeconds ?? DEFAULT_DPOP_PROOF_CLOCK_TOLERANCE_SECONDS
  const proofJtiTtlMs = (maxTokenAge + clockTolerance) * 1000

  return {
    kind: 'dpop-proof-provider',
    name: 'default-dpop-proof-provider',
    single: true,
    proofJtiTtlMs,

    /**
     * Verifies a DPoP Proof JWT according to the RFC 9449 checks required by
     * the token and credential endpoint flows.
     *
     * The verification includes:
     * - JOSE header validation: `typ` must be `dpop+jwt`, `alg` must not be
     *   `none` or HMAC-based, and `jwk` must contain a public key only.
     * - JWT signature verification using the public key from the JOSE `jwk`.
     * - Required payload claims: `jti`, `iat`, `htm`, and `htu`.
     * - Request binding: `htm` must match the HTTP method and `htu` must match
     *   the target URI after RFC 9449 normalization.
     * - Access-token binding: when an access token is provided by the caller,
     *   `ath` must match the SHA-256 hash of that token.
     * - Optional nonce binding when the caller provides an expected nonce.
     *
     * The returned `jwkThumbprint` is later used for access-token `cnf.jkt`
     * binding and JTI replay-cache scoping.
     */
    async verifyProof(proofJwt, context): Promise<VerifiedDpopProof> {
      const verifyContext = DPoPProofVerifyContext(context)
      const proofHeader = decodeProtectedHeader(proofJwt)
      const proofAlg = proofHeader.alg
      if (typeof proofAlg !== 'string' || isProhibitedDpopProofAlg(proofAlg)) {
        throw raise('invalid_dpop_proof', {
          message: 'DPoP proof JWT alg must be an asymmetric signature algorithm.',
        })
      }
      if (proofHeader.typ !== DPOP_PROOF_TYP) {
        throw raise('invalid_dpop_proof', {
          message: `DPoP proof JWT typ must be "${DPOP_PROOF_TYP}".`,
        })
      }

      const jwk = proofHeader.jwk
      if (jwk === null || typeof jwk !== 'object' || Array.isArray(jwk)) {
        throw raise('invalid_dpop_proof', {
          message: 'DPoP proof JWT header must contain a public JWK.',
        })
      }
      if ('d' in jwk && jwk.d !== undefined) {
        throw raise('invalid_dpop_proof', {
          message: 'DPoP proof JWT header jwk must not contain a private key.',
        })
      }

      let verificationKey: CryptoKey | Uint8Array
      try {
        verificationKey = await importJWK(jwk as JsonWebKey, proofAlg)
      } catch (error) {
        throw raise('invalid_dpop_proof', {
          message:
            error instanceof Error
              ? `Failed to import DPoP proof JWK: ${error.message}`
              : 'Failed to import DPoP proof JWK.',
          cause: error,
        })
      }

      const verifiedProof = await jwtVerify(proofJwt, verificationKey, {
        algorithms: [proofAlg],
        typ: DPOP_PROOF_TYP,
        maxTokenAge,
        clockTolerance,
      }).catch((error: unknown) => {
        throw raise('invalid_dpop_proof', {
          message:
            error instanceof Error
              ? `DPoP proof JWT verification failed: ${error.message}`
              : 'DPoP proof JWT verification failed.',
          cause: error,
        })
      })

      const payload = parseDpopProofPayload(verifiedProof.payload)

      if (payload.htm !== verifyContext.htm.toUpperCase()) {
        throw raise('invalid_dpop_proof', {
          message: 'DPoP proof JWT htm claim does not match the HTTP method.',
        })
      }
      if (normalizeHtu(payload.htu) !== normalizeHtu(verifyContext.htu)) {
        throw raise('invalid_dpop_proof', {
          message: 'DPoP proof JWT htu claim does not match the target URI.',
        })
      }

      // RFC 9449 access-token binding for resource requests.
      // Token endpoint proof verification does not pass an access token, but
      // credential endpoint verification does, making `ath` required there.
      if (verifyContext.accessToken !== undefined) {
        if (!payload.ath) {
          throw raise('invalid_dpop_proof', {
            message: 'DPoP proof JWT ath claim is required.',
          })
        }
        if (payload.ath !== calculateAccessTokenHash(verifyContext.accessToken)) {
          throw raise('invalid_dpop_proof', {
            message: 'DPoP proof JWT ath claim does not match the access token.',
          })
        }
      }
      if (verifyContext.nonce !== undefined && payload.nonce !== verifyContext.nonce) {
        throw raise('invalid_dpop_proof', {
          message: 'DPoP proof JWT nonce claim does not match the expected nonce.',
        })
      }

      const jwkThumbprint = await calculateJwkThumbprint(jwk as JsonWebKey)
      return VerifiedDpopProof({
        jwkThumbprint,
        jti: payload.jti,
        iat: payload.iat,
        ...(typeof payload.nonce === 'string' ? { nonce: payload.nonce } : {}),
      })
    },
  }
}
