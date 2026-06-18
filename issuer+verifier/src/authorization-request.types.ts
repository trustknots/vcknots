import { z } from 'zod'
import { Dcql } from './dcql.type'
import { commonReqSchema } from './request-object.types'

// https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
// https://openid.net/specs/openid-4-verifiable-presentations-1_0-ID2.html#name-authorization-request
// https://openid.net/specs/openid-4-verifiable-presentations-1_0-ID2.html#section-5-10

const requestUriFlowSchema = z.object({
  client_id: z.string(),
  request_uri: z.string().url(),
})

const inlineDcqlFlowSchema = commonReqSchema
  .extend({
    client_id_scheme: z.string().optional(),
    client_metadata_uri: z.string().optional(),
  })
  .and(Dcql.schema)
  .superRefine((data, ctx) => {
    if (!data.nonce) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'nonce is required for inline DCQL flow',
        path: ['nonce'],
      })
    }
  })

const authorizationRequestSchema = z.union([requestUriFlowSchema, inlineDcqlFlowSchema])

export type AuthorizationRequest = z.infer<typeof authorizationRequestSchema>
export const AuthorizationRequest = (value?: unknown) => authorizationRequestSchema.parse(value)
AuthorizationRequest.schema = authorizationRequestSchema
