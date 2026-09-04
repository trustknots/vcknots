import { z } from 'zod'
import { DeepPartialUnknown } from './type.utils'
import { VerifierMetadata } from './verifier-metadata.types'
import { Dcql } from './dcql.type'

// https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
// https://www.rfc-editor.org/rfc/rfc9101.html
// https://www.rfc-editor.org/rfc/rfc6749.html

export const commonReqSchema = z.object({
  response_type: z.union([z.literal('vp_token'), z.literal('id_token'), z.string()]),
  client_id: z.string(),
  state: z.string().optional(),
  scope: z.string().optional(),
  client_metadata: VerifierMetadata.schema.optional(),
  transaction_data: z.array(z.string()).optional(),
  nonce: z.string(),
  response_mode: z.enum(['direct_post', 'query', 'fragment', 'dc_api.jwt', 'dc_api']),
  response_uri: z.string().url().optional(),
  redirect_uri: z.string().url().optional(),
})

const requestObjectSchema = commonReqSchema
  .extend({
    iss: z.string().optional(),
    aud: z.string().optional().or(z.array(z.string())),
    sub: z.string().optional(),
    exp: z.number().optional(),
    nbf: z.number().optional(),
    iat: z.number().optional(),
    jti: z.string().optional(),
    wallet_nonce: z.string().optional(),
    expected_origins: z.array(z.string()).optional(),
  })
  .and(Dcql.schema)

export type RequestObject = z.infer<typeof requestObjectSchema>
export const RequestObject = (value?: DeepPartialUnknown<RequestObject>) =>
  requestObjectSchema.parse(value)
RequestObject.schema = requestObjectSchema
