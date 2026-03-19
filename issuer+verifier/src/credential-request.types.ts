import { z } from 'zod'
import { proofsSchema } from './proofs.types'

// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-A.1
export enum CredentialFormats {
  JWT_VC_JSON = 'jwt_vc_json',
  JWT_VC_JSON_LD = 'jwt_vc_json-ld',
  LDP_VC = 'ldp_vc',
}

// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#name-credential-request
const credentialRequestSchema = z.object({
  credential_identifier: z.string().optional(),
  credential_configuration_id: z.string().optional(),
  proofs: proofsSchema.optional(),
  credential_response_encryption: z
    .object({
      jwk: z.string(),
      alg: z.string(),
      zip: z.string().optional(),
    })
    .optional(),
})

export type CredentialRequest = z.infer<typeof credentialRequestSchema>

export const CredentialRequest = (value?: {
  credential_identifier?: string
  credential_configuration_id?: string
  proofs?: {
    jwt?: string[]
    ldp_vp?: {
      holder?: string
      proof: {
        domain: string
        challenge: string
      }
    }[]
    attestation?: string[]
  }
  credential_response_encryption?: {
    jwk: string
    alg: string
    zip?: string
  }
}) => credentialRequestSchema.parse(value)
