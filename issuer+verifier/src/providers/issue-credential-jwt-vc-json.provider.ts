import { base64url } from 'jose'
import { randomUUID } from 'node:crypto'
import * as z from 'zod'
import { CredentialConfigurationSupported, CredentialIssuer } from '../credential-issuer.types'
import { CredentialFormats } from '../credential-request.types'
import { raise } from '../errors/vcknots.error'
import { IssueCredentialProvider, IssueCredentialCreateCredentialOptions } from './provider.types'
import { withProviderRegistry, WithProviderRegistry } from './provider.registry'
import { selectProvider } from './provider.utils'
import * as jose from 'jose'

export type IssueCredentialProviderOptions = {
  identifier?: () => string
}

const getClaimValue = (claims: Record<string, unknown>, path: string[]): unknown => {
  let current: unknown = claims
  for (const segment of path) {
    if (typeof current !== 'object' || current === null || !(segment in current)) {
      return undefined
    }
    current = (current as Record<string, unknown>)[segment]
  }
  return current
}

const setClaimValue = (target: Record<string, unknown>, path: string[], value: unknown): void => {
  let current = target
  for (const segment of path.slice(0, -1)) {
    const next = current[segment]
    if (typeof next !== 'object' || next === null || Array.isArray(next)) {
      current[segment] = {}
    }
    current = current[segment] as Record<string, unknown>
  }
  current[path[path.length - 1]] = value
}

export const issueCredentialJwt = (
  providerOptions?: IssueCredentialProviderOptions
): IssueCredentialProvider & WithProviderRegistry => {
  if (providerOptions?.identifier) {
    const id = providerOptions.identifier()
    if (!z.string().url().safeParse(id).success) {
      throw raise('INVALID_OPTIONS', {
        message: 'Identifier must be a valid URL.',
      })
    }
  }
  return {
    kind: 'issue-credential-provider',
    name: 'default-issue-credential-w3c-jwt-vc-json-provider',
    single: false,

    ...withProviderRegistry,

    async createCredential(
      credentialIssuer: CredentialIssuer,
      configuration: CredentialConfigurationSupported,
      options?: IssueCredentialCreateCredentialOptions
    ): Promise<string> {
      if (!configuration.credential_definition || configuration.format !== 'jwt_vc_json') {
        throw raise('INVALID_CONFIGURATION', {
          message: 'Invalid credential configuration.',
        })
      }
      const today = new Date()
      const credentialSubject: Record<string, unknown> = {}
      const defCredentialMetadataClaims = configuration.credential_metadata?.claims
      if (
        defCredentialMetadataClaims &&
        defCredentialMetadataClaims.length > 0 &&
        options?.claims
      ) {
        for (const claim of defCredentialMetadataClaims) {
          const value = getClaimValue(options.claims, claim.path)
          if (claim.mandatory === true && value === undefined) {
            throw raise('INVALID_CLAIMS', {
              message: `Claim ${claim.path.join('.')} is not defined as mandatory in the credential definition.`,
            })
          }
          if (value !== undefined) {
            setClaimValue(credentialSubject, claim.path, value)
          }
        }
      }

      const id = providerOptions?.identifier
        ? providerOptions.identifier()
        : `${credentialIssuer}/vc/${randomUUID().replaceAll('-', '')}`

      const verifiableCredential = {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        id,
        type: configuration.credential_definition.type,
        issuer: credentialIssuer,
        issuanceDate: today.toISOString(),
        credentialSubject: {
          ...(options?.subject ? { id: options.subject } : {}),
          ...credentialSubject,
        },
      }

      const keyAlg = options?.keyAlg ?? 'ES256'
      if (
        configuration.credential_signing_alg_values_supported &&
        !configuration.credential_signing_alg_values_supported.includes(keyAlg)
      ) {
        throw raise('UNSUPPORTED_ISSUER_KEY_ALG', {
          message: 'Unsupported key algorithm.',
        })
      }
      const keyStore$ = this.providers.get('issuer-signature-key-store-provider')
      const issuerKeys = await keyStore$.fetch(credentialIssuer)
      const keys = issuerKeys.find((keypair) => keypair.privateKey.alg === keyAlg)
      if (!keys) {
        throw raise('AUTHZ_ISSUER_KEY_NOT_FOUND', {
          message: 'Issuer key not found.',
        })
      }
      const kid = await jose.calculateJwkThumbprint(keys.publicKey)

      const jwtHeader = {
        alg: keyAlg,
        kid,
        typ: 'JWT',
      }
      const jwtPayload = {
        vc: verifiableCredential,
        iss: verifiableCredential.issuer,
        ...(options?.subject ? { sub: options.subject } : {}),
      }

      const key$ = this.providers.get('issuer-signature-key-provider')
      const keyProvider = selectProvider(key$, keyAlg)
      const signature = await keyProvider.sign(keys.privateKey, keyAlg, jwtPayload, jwtHeader)
      if (!signature) {
        throw raise('INTERNAL_SERVER_ERROR', {
          message: 'Cannot sign credentials.',
        })
      }
      const encode = (x: unknown) => base64url.encode(JSON.stringify(x))
      const credential = `${encode(jwtHeader)}.${encode(jwtPayload)}.${signature}`

      return credential
    },
    canHandle(format: CredentialFormats): boolean {
      return format === 'jwt_vc_json'
    },
  }
}
