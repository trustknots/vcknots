import { z } from 'zod'
import { PresentationSubmission } from './presentation-submission.types'
import { DeepPartialUnknown } from './type.utils'

// https://openid.net/specs/openid-4-verifiable-presentations-1_0-ID2.html#section-6.1
const vpTokenSchema = z.string().or(z.record(z.string(), z.unknown()))
const authorizationResponseSchema = z.object({
  vp_token: vpTokenSchema.or(z.array(vpTokenSchema)),
  presentation_submission: PresentationSubmission.schema.optional(),
  state: z.string().optional(),
})
export type AuthorizationResponse = z.infer<typeof authorizationResponseSchema>
export const AuthorizationResponse = (value?: DeepPartialUnknown<AuthorizationResponse>) =>
  authorizationResponseSchema.parse(value)
AuthorizationResponse.schema = authorizationResponseSchema
