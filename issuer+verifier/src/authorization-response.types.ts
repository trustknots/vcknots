import { z } from 'zod'
import { DeepPartialUnknown } from './type.utils'

// https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.3
// A single Verifiable Presentation: string (JWT/SD-JWT) or JSON object (JSON-LD/mdoc)
const verifiablePresentationSchema = z.union([z.string(), z.record(z.string(), z.unknown())])

// DCQL vp_token: JSON object mapping Credential Query IDs to arrays of VPs
// https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.4
const vpTokenSchema = z.record(z.string(), z.array(verifiablePresentationSchema))

const authorizationResponseSchema = z.object({
  vp_token: vpTokenSchema,
  state: z.string().optional(),
})
export type AuthorizationResponse = z.infer<typeof authorizationResponseSchema>
export const AuthorizationResponse = (value?: DeepPartialUnknown<AuthorizationResponse>) =>
  authorizationResponseSchema.parse(value)
AuthorizationResponse.schema = authorizationResponseSchema
