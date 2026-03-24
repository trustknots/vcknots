import * as z from 'zod'

export const verifiableCredentialSchema = <T extends z.ZodType>(t: T) =>
  z
    .object({
      '@context': z.array(z.string()),
      id: z.string().url().optional(),
      type: z.array(z.string()),
      issuer: z.string().url(),
      issuanceDate: z.string().datetime({ offset: true }),
    })
    .and(t)

export const jwtVcJsonSchema = <T extends z.ZodType>(t: T) =>
  z.object({
    credentialSubject: z
      .object({
        id: z.string().url(),
      })
      .and(t)
      .optional(),
  })

const jwtVcJsonHeaderSchema = z.object({
  alg: z.string(),
  typ: z.literal('JWT'),
  kid: z.string().optional(),
})

const jwtVcJsonBodySchema = <T extends z.ZodType>(t: T) =>
  z.object({
    vc: verifiableCredentialSchema(jwtVcJsonSchema(t)),
    iss: z.string(), // issuer
    sub: z.string(), // id contained in the credentialSubject
    nbf: z.number().optional(), // issuanceDate
    exp: z.number().optional(), // expirationDate
    jti: z.string().optional(), // id of the verifiable credential
  })

export type VerifiableCredential<T extends Record<string, unknown> = Record<string, unknown>> =
  z.infer<ReturnType<typeof verifiableCredentialSchema<z.ZodType<T>>>>

export type JwtVcJson<T extends Record<string, unknown> = Record<string, unknown>> = z.infer<
  ReturnType<typeof jwtVcJsonSchema<z.ZodType<T>>>
>
export type JwtVcJsonHeader = z.infer<typeof jwtVcJsonHeaderSchema>
export type JwtVcJsonBody<T extends Record<string, unknown> = Record<string, unknown>> = z.infer<
  ReturnType<typeof jwtVcJsonBodySchema<z.ZodType<T>>>
>

enum CredentialFormats {
  JWT_VC_JSON = 'jwt_vc_json',
  JWT_VC_JSON_LD = 'jwt_vc_json-ld',
  LDP_VC = 'ldp_vc',
}

interface ProofTypeJwt {
  jwt: {
    proof_signing_alg_values_supported: string[]
  }
}
// https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-metadata
export interface IssuerCredentialConfiguration {
  format: CredentialFormats
  scope?: string
  cryptographic_binding_methods_supported?: string[]
  credential_signing_alg_values_supported?: string[]
  proof_types_supported?: ProofTypeJwt
  display?: {
    name: string
    locale?: string
    logo?: {
      uri?: string
      alt_text?: string
    }
    description?: string
    background_color?: string
    background_image?: string
    text_color?: string
  }[]

  // Custom implementation for jwt_vc_json
  credential_definition: {
    type: string[]
    credentialSubject?: {
      [name: string]: {
        mandatory?: boolean
        value_type?: string
        display?: { name?: string; locale?: string }[]
      }
    }
  }
  order?: string[]
}

const jwkSchema = z
  .object({
    e: z.string().optional(),
    n: z.string().optional(),
    kty: z.string().optional(),
    x: z.string().optional(),
    y: z.string().optional(),
    crv: z.string().optional(),
  })
  .and(z.record(z.string(), z.unknown()))

const proofJwtHeaderSchema = z.object({
  alg: z.string(),
  typ: z.string().optional(),
  kid: z.string().optional(),
  jwk: jwkSchema.optional(),
  x5c: z.array(z.string()).optional(),
  trust_chain: z.array(z.string()).optional(),
})

const proofJwtBodySchema = z.object({
  iss: z.string().optional(),
  aud: z.string().optional().or(z.array(z.string())),
  iat: z.number().optional(),
  nonce: z.string().optional(),
})

const proofJwtSchema = z.object({
  header: proofJwtHeaderSchema,
  payload: proofJwtBodySchema,
})
export type ProofJwtHeader = z.infer<typeof proofJwtHeaderSchema>
export type ProofJwtBody = z.infer<typeof proofJwtBodySchema>
export type ProofJwt = z.infer<typeof proofJwtSchema>

const verifiableCredentialBaseSchema = z
  .object({
    '@context': z.array(z.string()),
    id: z.string().url().optional(),
    type: z.array(z.string()),
    issuer: z.string().url(),
    issuanceDate: z.string().datetime({ offset: true }),
  })
  .passthrough()

export function parseVerifiableCredentialBase(input: unknown): input is VerifiableCredential {
  const result = verifiableCredentialBaseSchema.safeParse(input)
  if (!result.success) {
    return false
  }
  return true
}
