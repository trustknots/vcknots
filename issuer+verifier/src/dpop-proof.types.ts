import { z } from 'zod'
import { DeepPartialUnknown } from './type.utils'

export type ParsedDpopHeader =
  | { ok: true; proofJwt: string }
  | { ok: false; reason: 'missing' | 'duplicate' | 'malformed' }

const dpopProofVerifyContextSchema = z.object({
  htm: z.string(),
  htu: z.string(),
  nonce: z.string().optional(),
  accessToken: z.string().optional(),
})

/**
 * Server-side verification input for a DPoP Proof JWT.
 *
 * These values are not claims extracted from the proof. They represent the
 * HTTP request context that the proof must be bound to:
 * - `htm`: expected HTTP method.
 * - `htu`: expected target URI.
 * - `nonce`: optional expected DPoP nonce value.
 * - `accessToken`: optional access token to bind with the proof `ath` claim.
 */
export type DPoPProofVerifyContext = z.infer<typeof dpopProofVerifyContextSchema>
export const DPoPProofVerifyContext = (
  value?: DeepPartialUnknown<DPoPProofVerifyContext>
) => dpopProofVerifyContextSchema.parse(value)
DPoPProofVerifyContext.schema = dpopProofVerifyContextSchema

const dpopProofPayloadSchema = z.object({
  jti: z.string().min(1),
  iat: z.number(),
  htm: z.string().min(1),
  htu: z.string().min(1),
  nonce: z.string().optional(),
  // Access-token hash claim. Required only when the caller provides accessToken.
  ath: z.string().min(1).optional(),
})

/**
 * DPoP Proof JWT payload claims that must exist before RFC 9449 request binding
 * checks are performed by the provider.
 */
export type DPoPProofPayload = z.infer<typeof dpopProofPayloadSchema>
export const DPoPProofPayload = (value?: unknown) => dpopProofPayloadSchema.parse(value)
DPoPProofPayload.schema = dpopProofPayloadSchema

const verifiedDpopProofSchema = z.object({
  jwkThumbprint: z.string(),
  jti: z.string(),
  iat: z.number(),
  nonce: z.string().optional(),
})

/**
 * Verification result extracted from a successfully verified DPoP Proof JWT.
 */
export type VerifiedDpopProof = z.infer<typeof verifiedDpopProofSchema>
export const VerifiedDpopProof = (value?: DeepPartialUnknown<VerifiedDpopProof>) =>
  verifiedDpopProofSchema.parse(value)
VerifiedDpopProof.schema = verifiedDpopProofSchema
