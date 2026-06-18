import { z } from 'zod'
import { Dcql } from './dcql.type'
import { DeepPartialUnknown } from './type.utils'
import { commonReqSchema } from './request-object.types'

// https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
// https://openid.net/specs/openid-4-verifiable-presentations-1_0-ID2.html#name-authorization-request
// https://openid.net/specs/openid-4-verifiable-presentations-1_0-ID2.html#section-5-10

const authorizationRequestSchema = commonReqSchema
  .extend({
    response_type: z.union([z.literal('vp_token'), z.literal('id_token'), z.string()]).optional(),
    client_id_scheme: z.string().optional(),
    client_metadata_uri: z.string().optional(),
    response_mode: z.enum(['direct_post', 'query', 'fragment']).optional(),
    request_uri: z.string().url().optional(),
  })
  .and(Dcql.schema)
  .superRefine((data, ctx) => {
    if (!data.request_uri && !data.nonce && !data.response_type) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'When request_uri is not present, response_type or nonce is required',
        path: ['nonce', 'response_type'],
      })
    }
  })
export type AuthorizationRequest = z.infer<typeof authorizationRequestSchema>
export const AuthorizationRequest = (value?: DeepPartialUnknown<AuthorizationRequest>) =>
  authorizationRequestSchema.parse(value)
AuthorizationRequest.schema = authorizationRequestSchema
