import { z } from 'zod'

// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#appendix-A.1
export enum CredentialFormats {
  JWT_VC_JSON = 'jwt_vc_json',
  JWT_VC_JSON_LD = 'jwt_vc_json-ld',
  LDP_VC = 'ldp_vc',
  DC_SD_JWT = 'dc+sd-jwt',
}

export enum ProofTypes {
  JWT = 'jwt',
  LDP_VP = 'ldp_vp',
}

// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#name-credential-request
const credentialRequestCommonSchema = z.object({
  credential_identifier: z.string().optional(),
  format: z.nativeEnum(CredentialFormats).optional(),
  proof: z
    .object({
      proof_type: z.nativeEnum(ProofTypes),
    })
    .optional(),
  credential_response_encryption: z
    .object({
      jwk: z.string(),
      alg: z.string(),
      enc: z.string(),
    })
    .optional(),
})

const credentialRequestJwtVcJsonSchema = z.object({
  credential_definition: z.object({
    type: z.array(z.string()),
    credentialSubject: z.record(z.string(), z.string()).optional(),
  }),
})

const credentialRequestProofJwt = z.object({
  proof: z
    .object({
      jwt: z.string().optional(),
    })
    .optional(),
})

const credentialRequestProofLdpVp = z.object({
  proof: z
    .object({
      ldp_vp: z
        .object({
          holder: z.string().optional(),
          proof: z.object({
            domain: z.string(),
            challenge: z.string(),
          }),
        })
        .optional(),
    })
    .optional(),
})

const credentialRequestSchema = credentialRequestCommonSchema
  .and(credentialRequestJwtVcJsonSchema)
  .and(credentialRequestProofJwt)
  .and(credentialRequestProofLdpVp)

export type CredentialRequest = z.infer<typeof credentialRequestSchema>

export const CredentialRequest = (value?: {
  credential_identifier?: string
  format?: CredentialFormats
  proof?: {
    proof_type: ProofTypes
    jwt?: string
    ldp_vp?: {
      holder?: string
      proof: {
        domain: string
        challenge: string
      }
    }
  }
  credential_response_encryption?: {
    jwk: string
    alg: string
    enc: string
  }
}) => credentialRequestSchema.parse(value)
