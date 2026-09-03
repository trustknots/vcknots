import { base64url, exportJWK } from 'jose'
import { randomUUID } from 'node:crypto'
import * as z from 'zod'
import { CredentialConfigurationSupported, CredentialIssuer } from '../credential-issuer.types'
import { CredentialFormats } from '../credential-request.types'
import { raise } from '../errors/vcknots.error'
import { getClaimValue, setClaimValue } from './issue-credential.utils'
import { IssueCredentialProvider, IssueCredentialCreateCredentialOptions } from './provider.types'
import { withProviderRegistry, WithProviderRegistry } from './provider.registry'
import * as jose from 'jose'
import { jwkSchema } from '../jwk.type'

export type IssueCredentialProviderOptions = {
  identifier?: () => string
}

// const credentialSubjectPath = (path: string[]) =>
//   path[0] === 'credentialSubject' ? path.slice(1) : path

const credentialSubjectPath = (path: string[]) => {
  if (path[0] !== 'credentialSubject') {
    return path
  }
  const subjectPath = path.slice(1)
  if (subjectPath.length === 0) {
    throw raise('invalid_configuration', {
      message: 'credential_metadata.claims[].path must point to a claim under credentialSubject.',
    })
  }
  return subjectPath
}

export const issueCredentialJwt = (
  providerOptions?: IssueCredentialProviderOptions
): IssueCredentialProvider & WithProviderRegistry => {
  if (providerOptions?.identifier) {
    const id = providerOptions.identifier()
    if (!z.string().url().safeParse(id).success) {
      throw raise('invalid_options', {
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
        throw raise('invalid_configuration', {
          message: 'Invalid credential configuration.',
        })
      }
      const today = new Date()
      const credentialSubject: Record<string, unknown> = {}
      const claimsSource = options?.claims ?? {}
      const defCredentialMetadataClaims = configuration.credential_metadata?.claims
      if (defCredentialMetadataClaims && defCredentialMetadataClaims.length > 0) {
        for (const claim of defCredentialMetadataClaims) {
          const subjectPath = credentialSubjectPath(claim.path)
          let value = getClaimValue(claimsSource, claim.path)
          if (value === undefined && subjectPath.length !== claim.path.length) {
            value = getClaimValue(claimsSource, subjectPath)
          }
          // const value = getClaimValue(claimsSource, subjectPath)
          if (claim.mandatory === true && value === undefined) {
            throw raise('invalid_claims', {
              message: `Claim ${claim.path.join('.')} is not defined as mandatory in the credential definition.`,
            })
          }
          if (value !== undefined) {
            setClaimValue(credentialSubject, subjectPath, value)
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
          ...(options?.subject !== undefined ? { id: options.subject } : {}),
          ...credentialSubject,
        },
      }

      const keyAlg = options?.keyAlg ?? 'ES256'
      if (
        configuration.credential_signing_alg_values_supported &&
        !configuration.credential_signing_alg_values_supported.includes(keyAlg)
      ) {
        throw raise('unsupported_issuer_key_alg', {
          message: 'Unsupported key algorithm.',
        })
      }
      const keyStore$ = this.providers.get('issuer-signature-key-store-provider')
      const issuerKey = await keyStore$.fetch(credentialIssuer, keyAlg)
      if (!issuerKey) {
        throw raise('authz_issuer_key_not_found', {
          message: 'Issuer key not found.',
        })
      }
      const jwk = jwkSchema.parse(await exportJWK(issuerKey))
      const kid = await jose.calculateJwkThumbprint(jwk)

      const jwtHeader = {
        alg: keyAlg,
        kid,
        typ: 'JWT',
      }
      const jwtPayload = {
        vc: verifiableCredential,
        iss: verifiableCredential.issuer,
        ...(options?.subject !== undefined ? { sub: options.subject } : {}),
      }

      const signature = await keyStore$.sign(credentialIssuer, keyAlg, jwtPayload, jwtHeader)
      if (!signature) {
        throw raise('internal_server_error', {
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
