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

export const parseAuthorizationServerIssuer = (value: unknown) => {
  try {
    return AuthorizationServerIssuer(value as string)
  } catch (e) {
    if (e instanceof z.ZodError) {
      invalidRequest('Invalid issuer parameter.', e)
    }
    throw e
  }
}

export const parseCredentialIssuer = (value: unknown) => {
  try {
    return CredentialIssuer(value as string)
  } catch (e) {
    if (e instanceof z.ZodError) {
      invalidRequest('Invalid issuer parameter.', e)
    }
    throw e
  }
}

export const parseVerifierClientId = (value: unknown) => {
  try {
    return ClientId(value)
  } catch (e) {
    if (e instanceof z.ZodError) {
      invalidRequest('Invalid verifier parameter.', e)
    }
    throw e
  }
}

export const parseRequestObjectId = (value: unknown) => {
  try {
    return RequestObjectId(value as string)
  } catch (e) {
    if (e instanceof z.ZodError) {
      invalidRequest('Invalid request object id parameter.', e)
    }
    throw e
  }
}

export const parseCredentialConfigurationId = (value: unknown) => {
  try {
    return CredentialConfigurationId(value as string)
  } catch (e) {
    if (e instanceof z.ZodError) {
      throw err('invalid_request', {
        message: 'Invalid credential configuration id parameter.',
        cause: e,
      })
    }
    throw e
  }
}

export const parseCredentialIssuerMetadata = (value: unknown) => {
  try {
    return CredentialIssuerMetadata(value as Record<string, unknown>)
  } catch (e) {
    if (e instanceof z.ZodError) {
      throw err('invalid_request', {
        message: 'Invalid credential issuer metadata.',
        cause: e,
      })
    }
    throw e
  }
}

export const parseAuthorizationServerMetadata = (value: unknown) => {
  try {
    return AuthorizationServerMetadata(value as Record<string, unknown>)
  } catch (e) {
    if (e instanceof z.ZodError) {
      throw err('invalid_request', {
        message: 'Invalid authorization server metadata.',
        cause: e,
      })
    }
    throw e
  }
}

export const parseVerifierMetadata = (value: unknown) => {
  try {
    return VerifierMetadata(value as Record<string, unknown>)
  } catch (e) {
    if (e instanceof z.ZodError) {
      throw err('invalid_request', {
        message: 'Invalid verifier metadata.',
        cause: e,
      })
    }
    throw e
  }
}
