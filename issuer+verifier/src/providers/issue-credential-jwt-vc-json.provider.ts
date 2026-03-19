import { randomUUID } from 'node:crypto'
import * as z from 'zod'
import { CredentialConfiguration, CredentialIssuer } from '../credential-issuer.types'
import { CredentialFormats } from '../credential-request.types'
import { JwtVcJson, VerifiableCredential } from '../credential.types'
import { raise } from '../errors/vcknots.error'
import { IssueCredentialProvider, IssueCredentialCreateCredentialOptions } from './provider.types'

export type IssueCredentialProviderOptions = {
  identifier?: () => string
}

export const issueCredentialJwt = (
  providerOptions?: IssueCredentialProviderOptions
): IssueCredentialProvider => {
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

    createCredential(
      credentialIssuer: CredentialIssuer,
      configuration: CredentialConfiguration,
      options?: IssueCredentialCreateCredentialOptions
    ): VerifiableCredential<JwtVcJson> {
      const today = new Date()
      const credentialSubject: Record<string, unknown> = {}
      const defCredentialSubject = configuration.credential_definition.credentialSubject
      if (options?.subject) {
        credentialSubject.id = options.subject
      }
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
          ...credentialSubject,
        },
      }

      return verifiableCredential
    },
    canHandle(format: CredentialFormats): boolean {
      return format === 'jwt_vc_json'
    },
  }
}
