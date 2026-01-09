import { z } from 'zod'

// https://openid.net/specs/openid-4-verifiable-presentations-1_0-ID2.html#name-verifier-metadata-client-me
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
            kid: z.string().optional(),
          })
          .and(z.record(z.string(), z.unknown()))
          .optional()
      ),
    })
    .optional(),
  software_id: z.string().optional(),
  software_version: z.string().optional(),
  response_types: z.enum(['code', 'token']).optional(),
  vp_formats: z.record(z.string(), z.unknown()),
  authorization_signed_response_alg: z.string().optional(), // mentioned in OID4VP draft24
  authorization_encrypted_response_alg: z.string().optional(), // mentioned in OID4VP draft24
  authorization_encrypted_response_enc: z.string().optional(), // mentioned in OID4VP draft24
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
    }[]
  }
  software_id?: string
  software_version?: string
  response_types?: string[]
  vp_formats?: Record<string, unknown>
  authorization_signed_response_alg?: string
  authorization_encrypted_response_alg?: string
  authorization_encrypted_response_enc?: string
}) => verifierMetadataSchema.parse(value)
VerifierMetadata.schema = verifierMetadataSchema
