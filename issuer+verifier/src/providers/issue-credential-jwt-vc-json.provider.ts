import { base64url } from 'jose'
import { randomUUID } from 'node:crypto'
import * as z from 'zod'
import { CredentialConfiguration, CredentialIssuer } from '../credential-issuer.types'
import { CredentialFormats } from '../credential-request.types'
import { raise } from '../errors/vcknots.error'
import { IssueCredentialProvider, IssueCredentialCreateCredentialOptions } from './provider.types'
import { withProviderRegistry, WithProviderRegistry } from './provider.registry'
import { selectProvider } from './provider.utils'

export type IssueCredentialProviderOptions = {
  identifier?: () => string
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
      configuration: CredentialConfiguration,
      options?: IssueCredentialCreateCredentialOptions
    ): Promise<string> {
      const today = new Date()
      const credentialSubject: Record<string, unknown> = {}
      const defCredentialSubject = configuration.credential_definition.credentialSubject
      if (defCredentialSubject && Object.keys(defCredentialSubject).length > 0 && options?.claims) {
        for (const [key, value] of Object.entries(defCredentialSubject)) {
          if (value.mandatory === true && !(key in options.claims)) {
            throw raise('INVALID_CLAIMS', {
              message: `Claim ${key} is not defined as mandatory in the credential definition.`,
            })
          }
          if (key in options.claims) {
            // unsupported  image media types such as image/jpeg as defined in IANA media type registry for images (https://www.iana.org/assignments/media-types/media-types.xhtml#image)
            if (value.value_type === 'string') {
              credentialSubject[key] = String(options.claims[key])
            } else if (value.value_type === 'number') {
              credentialSubject[key] = Number(options.claims[key])
            } else {
              credentialSubject[key] = options.claims[key]
            }
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
      const jwtHeader = {
        alg: keyAlg,
        typ: 'JWT',
      }
      const jwtPayload = {
        vc: verifiableCredential,
        iss: verifiableCredential.issuer,
        ...(options?.subject ? { sub: options.subject } : {}),
      }
      const keyStore$ = this.providers.get('issuer-signature-key-store-provider')
      const issuerKeys = await keyStore$.fetch(credentialIssuer)
      const keys = issuerKeys.find((keypair) => keypair.privateKey.alg === keyAlg)
      if (!keys) {
        throw raise('AUTHZ_ISSUER_KEY_NOT_FOUND', {
          message: 'Issuer key not found.',
        })
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
