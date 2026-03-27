import { z } from 'zod'

export enum ProofTypes {
  JWT = 'jwt',
  DI_VP = 'di_vp',
  ATTESTATION = 'attestation',
}

const compactJwtSchema = z
  .string()
  .min(1)
  .regex(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/, 'Must be a compact JWT/JWS string')

const dataIntegrityProofSchema = z
  .object({
    type: z.string().min(1).optional(),
    cryptosuite: z.string().min(1),
    proofPurpose: z.literal('authentication'),
    verificationMethod: z.string().min(1).optional(),
    created: z.string().min(1).optional(),
    domain: z.string().min(1),
    challenge: z.string().min(1).optional(),
    proofValue: z.string().min(1).optional(),
  })
  .passthrough()

const diVpSchema = z
  .object({
    '@context': z.array(z.string().min(1)).min(1).optional(),
    type: z.array(z.string().min(1)).min(1).optional(),
    holder: z.string().min(1).optional(),
    proof: z.union([dataIntegrityProofSchema, z.array(dataIntegrityProofSchema).min(1)]),
  })
  .passthrough()

const jwtProofsSchema = z
  .object({
    [ProofTypes.JWT]: z.array(compactJwtSchema).min(1),
  })
  .strict()

const diVpProofsSchema = z
  .object({
    [ProofTypes.DI_VP]: z.array(diVpSchema).min(1),
  })
  .strict()

const attestationProofsSchema = z
  .object({
    [ProofTypes.ATTESTATION]: z.array(compactJwtSchema).length(1),
  })
  .strict()

export const proofsSchema = z.union([jwtProofsSchema, diVpProofsSchema, attestationProofsSchema])

export type Proofs = z.infer<typeof proofsSchema>
export type DataIntegrityProof = z.infer<typeof dataIntegrityProofSchema>
export type DiVpProof = z.infer<typeof diVpSchema>
