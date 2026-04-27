import { calculateJwkThumbprint, decodeProtectedHeader, importJWK, jwtVerify } from 'jose'
import type { VerifiedDpopProof } from '../dpop-proof.types'
import { raise } from '../errors/vcknots.error'
import type { DPoPProofProvider } from './provider.types'

const DPOP_PROOF_TYP = 'dpop+jwt'
const DEFAULT_DPOP_PROOF_MAX_TOKEN_AGE_SECONDS = 300
const DEFAULT_DPOP_PROOF_CLOCK_TOLERANCE_SECONDS = 60

function isProhibitedDpopProofAlg(alg: string): boolean {
  const trimmed = alg.trim()
  if (trimmed.length === 0) return true
  if (trimmed.toLowerCase() === 'none') return true
  return /^hs/i.test(trimmed)
}
/**
 * RFC 9449 §4.3 の `htu` 比較用: fragment 除去、クエリ除去、末尾 `/` の揃え。
 * （§4.3 検証項目 9: リクエスト URI と一致、query と fragment は無視）
 */
function normalizeHtu(value: string): string {
  let normalized: URL
  try {
    normalized = new URL(value)
  } catch (error) {
    throw raise('INVALID_DPOP_PROOF', {
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

export type DPoPProofFactoryOptions = {
  maxTokenAgeSeconds?: number
  clockToleranceSeconds?: number
}

export const dpopProof = (factoryOptions?: DPoPProofFactoryOptions): DPoPProofProvider => {
  const maxTokenAge =
    factoryOptions?.maxTokenAgeSeconds ?? DEFAULT_DPOP_PROOF_MAX_TOKEN_AGE_SECONDS
  const clockTolerance =
    factoryOptions?.clockToleranceSeconds ?? DEFAULT_DPOP_PROOF_CLOCK_TOLERANCE_SECONDS
  const proofJtiTtlMs = (maxTokenAge + clockTolerance) * 1000

  return {
    kind: 'dpop-proof-provider',
    name: 'default-dpop-proof-provider',
    single: true,
    proofJtiTtlMs,

    async verifyProof(proofJwt, context): Promise<VerifiedDpopProof> {
      const proofHeader = decodeProtectedHeader(proofJwt)
      const proofAlg = proofHeader.alg
      if (typeof proofAlg !== 'string' || isProhibitedDpopProofAlg(proofAlg)) {
        throw raise('INVALID_DPOP_PROOF', {
          message: 'DPoP proof JWT alg must be an asymmetric signature algorithm.',
        })
      }
      if (proofHeader.typ !== DPOP_PROOF_TYP) {
        throw raise('INVALID_DPOP_PROOF', {
          message: `DPoP proof JWT typ must be "${DPOP_PROOF_TYP}".`,
        })
      }

      const jwk = proofHeader.jwk
      if (jwk === null || typeof jwk !== 'object' || Array.isArray(jwk)) {
        throw raise('INVALID_DPOP_PROOF', {
          message: 'DPoP proof JWT header must contain a public JWK.',
        })
      }
      if ('d' in jwk && jwk.d !== undefined) {
        throw raise('INVALID_DPOP_PROOF', {
          message: 'DPoP proof JWT header jwk must not contain a private key.',
        })
      }

      let verificationKey: CryptoKey | Uint8Array
      try {
        verificationKey = await importJWK(jwk as JsonWebKey, proofAlg)
      } catch (error) {
        throw raise('INVALID_DPOP_PROOF', {
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
        throw raise('INVALID_DPOP_PROOF', {
          message:
            error instanceof Error
              ? `DPoP proof JWT verification failed: ${error.message}`
              : 'DPoP proof JWT verification failed.',
          cause: error,
        })
      })

      const payload = verifiedProof.payload
      if (typeof payload.jti !== 'string' || payload.jti.trim().length === 0) {
        throw raise('INVALID_DPOP_PROOF', {
          message: 'DPoP proof JWT jti claim is required.',
        })
      }
      if (typeof payload.iat !== 'number') {
        throw raise('INVALID_DPOP_PROOF', {
          message: 'DPoP proof JWT iat claim is required.',
        })
      }
      if (typeof payload.htm !== 'string' || payload.htm !== context.htm.toUpperCase()) {
        throw raise('INVALID_DPOP_PROOF', {
          message: 'DPoP proof JWT htm claim does not match the HTTP method.',
        })
      }
      if (typeof payload.htu !== 'string') {
        throw raise('INVALID_DPOP_PROOF', {
          message: 'DPoP proof JWT htu claim is required.',
        })
      }
      if (normalizeHtu(payload.htu) !== normalizeHtu(context.htu)) {
        throw raise('INVALID_DPOP_PROOF', {
          message: 'DPoP proof JWT htu claim does not match the target URI.',
        })
      }
      if (context.nonce !== undefined && payload.nonce !== context.nonce) {
        throw raise('INVALID_DPOP_PROOF', {
          message: 'DPoP proof JWT nonce claim does not match the expected nonce.',
        })
      }

      const jwkThumbprint = await calculateJwkThumbprint(jwk as JsonWebKey)
      return {
        jwkThumbprint,
        jti: payload.jti,
        iat: payload.iat,
        ...(typeof payload.nonce === 'string' ? { nonce: payload.nonce } : {}),
      }
    },
  }
}
