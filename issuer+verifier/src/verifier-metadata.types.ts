import { z } from 'zod'

// https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B
// Per-format metadata types for known credential format identifiers (Appendix B).
// Unknown format identifiers are allowed via the index signature.
type NonEmptyArray<T> = [T, ...T[]]

export type VpFormatsSupported = {
  jwt_vc_json?: { alg_values?: NonEmptyArray<string> }
  ldp_vc?: { proof_type_values?: NonEmptyArray<string>; cryptosuite_values?: NonEmptyArray<string> }
  mso_mdoc?: {
    issuerauth_alg_values?: NonEmptyArray<number>
    deviceauth_alg_values?: NonEmptyArray<number>
  }
  'dc+sd-jwt'?: {
    'sd-jwt_alg_values'?: NonEmptyArray<string>
    'kb-jwt_alg_values'?: NonEmptyArray<string>
  }
} & Record<string, unknown>

const nonEmptyStringArray = z.array(z.string()).min(1)
const nonEmptyNumberArray = z.array(z.number()).min(1)

// Schema for unknown format identifiers: any field value is accepted, but arrays must be non-empty
const unknownFormatFieldSchema = z
  .unknown()
  .refine((val) => !Array.isArray(val) || val.length > 0, {
    message: 'Arrays in vp_formats_supported must be non-empty',
  })
const unknownFormatSchema = z.record(z.string(), unknownFormatFieldSchema)

const vpFormatsSchema = z
  .object({
    jwt_vc_json: z
      .object({ alg_values: nonEmptyStringArray.optional() })
      .catchall(z.unknown())
      .optional(),
    ldp_vc: z
      .object({
        proof_type_values: nonEmptyStringArray.optional(),
        cryptosuite_values: nonEmptyStringArray.optional(),
      })
      .catchall(z.unknown())
      .optional(),
    mso_mdoc: z
      .object({
        issuerauth_alg_values: nonEmptyNumberArray.optional(),
        deviceauth_alg_values: nonEmptyNumberArray.optional(),
      })
      .catchall(z.unknown())
      .optional(),
    'dc+sd-jwt': z
      .object({
        'sd-jwt_alg_values': nonEmptyStringArray.optional(),
        'kb-jwt_alg_values': nonEmptyStringArray.optional(),
      })
      .catchall(z.unknown())
      .optional(),
  })
  .catchall(unknownFormatSchema)
  .refine((v) => Object.keys(v).length > 0, {
    message: 'vp_formats_supported must contain at least one format',
  })

// https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-verifier-metadata-client-me
// https://www.rfc-editor.org/rfc/rfc7591.html#section-2
export const verifierMetadataSchema = z.object({
  redirect_uris: z.array(z.string()).optional(),
  token_endpoint_auth_method: z
    .enum(['none', 'client_secret_post', 'client_secret_basic'])
    .optional(),
  grant_types: z
    .enum([
      'authorization_code',
      'implicit',
      'password',
      'client_credentials',
      'refresh_token',
      'urn:ietf:params:oauth:grant-type:jwt-bearer',
      'urn:ietf:params:oauth:grant-type:saml2-bearer',
    ])
    .optional(),
  client_name: z.string().optional(),
  client_uri: z.string().optional(),
  logo_uri: z.string().optional(),
  scope: z.string().optional(),
  contacts: z.array(z.string()).optional(),
  tos_uri: z.string().url().optional(),
  policy_uri: z.string().url().optional(),
  jwks_uri: z.string().url().optional(),
  jwks: z
    .object({
      keys: z.array(
        z
          .object({
            e: z.string().optional(),
            n: z.string().optional(),
            kty: z.string().optional(),
            x: z.string().optional(),
            y: z.string().optional(),
            crv: z.string().optional(),
            alg: z.string().optional(),
            kid: z.string(),
            use: z.string().optional(),
          })
          .and(z.record(z.string(), z.unknown()))
          .optional()
      ),
    })
    .optional(),
  software_id: z.string().optional(),
  software_version: z.string().optional(),
  response_types: z.enum(['code', 'token']).optional(),
  encrypted_response_enc_values_supported: z.array(z.string()).nonempty().optional(),
  vp_formats_supported: vpFormatsSchema,
})
export type VerifierMetadata = z.infer<typeof verifierMetadataSchema>
export const VerifierMetadata = (value?: {
  redirect_uris?: string[]
  token_endpoint_auth_method?: string
  grant_types?: string
  client_name?: string
  client_uri?: string
  logo_uri?: string
  scope?: string
  contacts?: string[]
  tos_uri?: string
  policy_uri?: string
  jwks_uri?: string
  jwks?: {
    keys?: {
      e?: string
      n?: string
      kty?: string
      x?: string
      y?: string
      crv?: string
      alg?: string
      kid: string
      use?: string
    }[]
  }
  software_id?: string
  software_version?: string
  response_types?: string[]
  encrypted_response_enc_values_supported?: string[]
  vp_formats_supported?: VpFormatsSupported
}) => verifierMetadataSchema.parse(value)
VerifierMetadata.schema = verifierMetadataSchema
