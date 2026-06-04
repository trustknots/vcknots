import { z } from 'zod'
import { AuthzClientPolicy } from './authz-oauth-policy.types'

const jwkSchema = z.record(z.string(), z.unknown())

const jwksSchema = z.object({
  keys: z.array(jwkSchema),
})

const authzOAuthClientSchema = z
  .object({
    client_id: z.string().min(1),
    client_name: z.string().optional(),
    token_endpoint_auth_method: z.string().optional(),
    token_endpoint_auth_signing_alg: z.string().optional(),
    client_assertion_audience: z.string().optional(),
    jwks: jwksSchema.optional(),
    jwks_uri: z.string().url().optional(),
    allowed_grant_types: z.array(z.string()).optional(),
    senderConstrainedAccessToken: AuthzClientPolicy.schema.shape.senderConstrainedAccessToken,
    enabled: z.boolean().optional(),
    comment: z.string().optional(),
  })
  .passthrough()

const authzOAuthClientsSchema = z.object({
  clients: z.array(authzOAuthClientSchema),
})

export type AuthzOAuthClient = z.infer<typeof authzOAuthClientSchema>
export const AuthzOAuthClient = (value?: unknown) => authzOAuthClientSchema.parse(value)
AuthzOAuthClient.schema = authzOAuthClientSchema

export type AuthzOAuthClients = z.infer<typeof authzOAuthClientsSchema>
export const AuthzOAuthClients = (value?: unknown) => authzOAuthClientsSchema.parse(value)
AuthzOAuthClients.schema = authzOAuthClientsSchema
