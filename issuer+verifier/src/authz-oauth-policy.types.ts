import { z } from 'zod'

const dpopModeSchema = z.enum(['off', 'optional', 'required'])
const senderConstraintMethodSchema = z.enum(['none', 'dpop', 'mtls'])

const dpopOptionsSchema = z.object({
  mode: dpopModeSchema.optional(),
})

const senderConstrainedAccessTokenOptionsSchema = z.object({
  method: senderConstraintMethodSchema.optional(),
  dpop: dpopOptionsSchema.optional(),
})

const authzClientPolicySchema = z.object({
  senderConstrainedAccessToken: senderConstrainedAccessTokenOptionsSchema.optional(),
})

export type AuthzClientPolicy = z.infer<typeof authzClientPolicySchema>
export const AuthzClientPolicy = (value?: unknown) => authzClientPolicySchema.parse(value)
AuthzClientPolicy.schema = authzClientPolicySchema

const authzOAuthPolicySchema = z.object({
  default_client: authzClientPolicySchema.optional(),
  anonymous_client: authzClientPolicySchema.optional(),
})

export type AuthzOAuthPolicy = z.infer<typeof authzOAuthPolicySchema>
export const AuthzOAuthPolicy = (value?: unknown) => authzOAuthPolicySchema.parse(value)
AuthzOAuthPolicy.schema = authzOAuthPolicySchema
