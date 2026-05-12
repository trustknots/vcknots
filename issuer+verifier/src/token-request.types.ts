import { z } from 'zod'
import { err } from './errors/vcknots.error'
import { PreAuthorizedCode } from './pre-authorized-code.types'
import { DeepPartialUnknown } from './type.utils'
export enum GrantType {
  PreAuthorizedCode = 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
  AuthorizationCode = 'authorization_code',
}

const preAuthorizedCodeTokenRequestSchema = z.object({
  grant_type: z.literal(GrantType.PreAuthorizedCode),
  'pre-authorized_code': PreAuthorizedCode.schema,
  tx_code: z.union([z.string(), z.number()]).optional(),
})

const authorizationCodeTokenRequestSchema = z.object({
  grant_type: z.literal(GrantType.AuthorizationCode),
  code: z.string(),
  redirect_uri: z.string().url().optional(),
  code_verifier: z.string().optional(),
})

const tokenResponseSchema = z.object({
  access_token: z.string(),
  token_type: z.string(), // BEARER
  expires_in: z.number(),
  refresh_token: z.string().optional(),
  scope: z.string().optional(),
  c_nonce: z.string().optional(),
  c_nonce_expires_in: z.number().optional(),
  // REQUIRED when the authorization_details parameter is used to request issuance of a certain Credential Configuration
  // authorization_details?: AuthorizationDetails
})

export type TokenRequest = z.infer<typeof tokenRequestSchema>
export type TokenRequestAuthorizationCode = z.infer<typeof authorizationCodeTokenRequestSchema>
export const TokenRequestAuthorizationCode = (
  value?: DeepPartialUnknown<TokenRequestAuthorizationCode>
) => authorizationCodeTokenRequestSchema.parse(value)
TokenRequestAuthorizationCode.schema = authorizationCodeTokenRequestSchema

export type TokenRequestPreAuthorizedCode = z.infer<typeof preAuthorizedCodeTokenRequestSchema>
export const TokenRequestPreAuthorizedCode = (
  value?: DeepPartialUnknown<TokenRequestPreAuthorizedCode>
) => {
  try {
    return preAuthorizedCodeTokenRequestSchema.parse(value)
  } catch (e) {
    if (e instanceof z.ZodError) {
      throw err('invalid_request', {
        message: 'Invalid token request parameters.',
        cause: e,
      })
    }
    throw e
  }
}

const tokenRequestSchema = authorizationCodeTokenRequestSchema.or(
  preAuthorizedCodeTokenRequestSchema
)

export const TokenRequest = (value?: DeepPartialUnknown<TokenRequest>) => {
  try {
    return tokenRequestSchema.parse(value)
  } catch (e) {
    if (e instanceof z.ZodError) {
      throw err('invalid_request', {
        message: 'Invalid token request parameters.',
        cause: e,
      })
    }
    throw e
  }
}

TokenRequest.schema = tokenRequestSchema

export type TokenResponse = z.infer<typeof tokenResponseSchema>

export const TokenResponse = (value?: {
  access_token?: string
  token_type?: string
  expires_in?: number
  refresh_token?: string
  scope?: string
  c_nonce?: string
  c_nonce_expires_in?: number
}) => tokenResponseSchema.parse(value)
TokenResponse.schema = tokenResponseSchema
