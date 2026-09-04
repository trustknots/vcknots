import { z } from 'zod'
import { Dcql } from './dcql.type'
import { commonReqSchema } from './request-object.types'

// https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.1
// https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5
// https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.6

const requestUriFlowSchema = z.object({
  client_id: z.string(),
  request_uri: z.string().url(),
  request_uri_method: z.enum(['get', 'post']).optional(),
})

const inlineDcqlFlowSchema = commonReqSchema.and(Dcql.schema)

const authorizationRequestSchema = z.union([requestUriFlowSchema, inlineDcqlFlowSchema])

export type AuthorizationRequest = z.infer<typeof authorizationRequestSchema>
export const AuthorizationRequest = (value?: unknown) => authorizationRequestSchema.parse(value)
AuthorizationRequest.schema = authorizationRequestSchema
