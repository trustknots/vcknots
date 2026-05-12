import { z } from 'zod'
import { err } from './errors/vcknots.error'
import {
  AuthorizationServerIssuer,
  AuthorizationServerMetadata,
} from './authorization-server.types'
import { CredentialIssuer, CredentialIssuerMetadata } from './credential-issuer.types'
import { ClientId } from './client-id.types'
import { RequestObjectId } from './request-object-id.types'
import { CredentialConfigurationId } from './credential-issuer.types'
import { VerifierMetadata } from './verifier.flows'

const invalidRequest = (message: string, cause?: unknown): never => {
  throw err('invalid_request', { message, cause })
}

function wrapInvalidRequest<T>(parser: (value: unknown) => T, message: string) {
  return (value: unknown): T => {
    try {
      return parser(value)
    } catch (e) {
      if (e instanceof z.ZodError) {
        invalidRequest(message, e)
      }
      throw e
    }
  }
}

export const parseAuthorizationServerIssuer = wrapInvalidRequest(
  (value) => AuthorizationServerIssuer(value as string),
  'Invalid issuer parameter.'
)

export const parseCredentialIssuer = wrapInvalidRequest(
  (value) => CredentialIssuer(value as string),
  'Invalid issuer parameter.'
)

export const parseVerifierClientId = wrapInvalidRequest(
  (value) => ClientId(value),
  'Invalid verifier parameter.'
)

export const parseRequestObjectId = wrapInvalidRequest(
  (value) => RequestObjectId(value as string),
  'Invalid request object id parameter.'
)

export const parseCredentialConfigurationId = wrapInvalidRequest(
  (value) => CredentialConfigurationId(value as string),
  'Invalid credential configuration id parameter.'
)

export const parseCredentialIssuerMetadata = wrapInvalidRequest(
  (value) => CredentialIssuerMetadata(value as Record<string, unknown>),
  'Invalid credential issuer metadata.'
)

export const parseAuthorizationServerMetadata = wrapInvalidRequest(
  (value) => AuthorizationServerMetadata(value as Record<string, unknown>),
  'Invalid authorization server metadata.'
)

export const parseVerifierMetadata = wrapInvalidRequest(
  (value) => VerifierMetadata(value as Record<string, unknown>),
  'Invalid verifier metadata.'
)
