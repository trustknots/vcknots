import { base64url } from 'jose'
import * as z from 'zod'
import { CredentialConfigurationSupported, CredentialIssuer } from '../credential-issuer.types'
import { CredentialFormats } from '../credential-request.types'
import { raise } from '../errors/vcknots.error'
import { IssueCredentialProvider, IssueCredentialCreateCredentialOptions } from './provider.types'
import { withProviderRegistry, WithProviderRegistry } from './provider.registry'
import { selectProvider } from './provider.utils'
import * as crypto from 'node:crypto'
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

const SALT_BYTE_SIZE = 128 / 8

const createDisclosures = (
  hashAlg: string,
  claimValues: Record<string, unknown>,
  target: Record<string, unknown>
): string[] => {
  const disclosures: string[] = []
  const sdDigests: string[] = []
  for (const [claimName, claimValue] of Object.entries(claimValues)) {
    const disclosureArray = [
      jose.base64url.encode(crypto.randomBytes(SALT_BYTE_SIZE)),
      claimName,
      claimValue,
    ]
    const disclosure = encodeDisclosure(disclosureArray)
    disclosures.push(disclosure)
    sdDigests.push(hashDisclosure(hashAlg, disclosure))
  }

  Object.defineProperty(target, '_sd', {
    value: sdDigests.sort(),
    enumerable: true,
  })

  return disclosures
}

const encodeDisclosure = (disclosureArray: unknown[]): string =>
  jose.base64url.encode(JSON.stringify(disclosureArray))

const ianaToCryptoAlg = (hashAlg: string): string => hashAlg.replace('-', '').toLowerCase()

const hashDisclosure = (alg: string, disclosure: string): string =>
  jose.base64url.encode(crypto.createHash(ianaToCryptoAlg(alg)).update(disclosure).digest())

export const issueCredentialSDJWT = (
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
    name: 'issue-credential-dc-sd-jwt-provider',
    single: false,

    ...withProviderRegistry,

    async createCredential(
      credentialIssuer: CredentialIssuer,
      configuration: CredentialConfigurationSupported,
      options?: IssueCredentialCreateCredentialOptions
    ): Promise<string> {
      if (!configuration.vct || configuration.format !== 'dc+sd-jwt') {
        throw raise('INVALID_CONFIGURATION', {
          message: 'Invalid credential configuration.',
        })
      }
      const vct = configuration.vct
      const nonDisclosableClaims = options?.nonDisclosableClaims ?? []

      let holderJwk = {}
      if (configuration.cryptographic_binding_methods_supported) {
        if (!options?.proofHeader) {
          throw raise('INVALID_OPTIONS', {
            message:
              'holderJwk must be provided in options when cryptographic binding is supported.',
          })
        }
        if (options.proofHeader.jwk) {
          if (!configuration.cryptographic_binding_methods_supported.includes('jwk')) {
            throw raise('UNSUPPORTED_CRYPTOGRAPHIC_BINDING_METHOD', {
              message: 'Unsupported cryptographic binding method detected.',
            })
          }
          holderJwk = options.proofHeader.jwk
        } else if (options.proofHeader.kid) {
          const didSplit = options.proofHeader.kid.split(':')
          if (didSplit.length < 3 || didSplit[0] !== 'did') {
            throw raise('INVALID_PROOF', {
              message: `Invalid DID format: ${options.proofHeader.kid}`,
            })
          }
          if (
            !configuration.cryptographic_binding_methods_supported.includes(`did:${didSplit[1]}`)
          ) {
            throw raise('UNSUPPORTED_CRYPTOGRAPHIC_BINDING_METHOD', {
              message: 'Unsupported cryptographic binding method detected.',
            })
          }
          const did$ = this.providers.get('did-provider')
          const didProvider = selectProvider(did$, didSplit[1])
          const didDoc = await didProvider.resolveDid(options.proofHeader.kid)
          if (
            !didDoc ||
            !didDoc.verificationMethod ||
            didDoc.verificationMethod.length === 0 ||
            !didDoc.verificationMethod[0].publicKeyJwk
          ) {
            throw raise('INVALID_PROOF', {
              message: 'Unsupported did type detected.',
            })
          }
          holderJwk = didDoc.verificationMethod[0].publicKeyJwk
        }
      }

      const sdJwtClaims: Record<string, unknown> = {}
      const disclosableClaims: Record<string, unknown> = {}
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
          if (value === undefined) {
            continue
          }

          const rootClaimName = claim.path[0]
          const rootValue = getClaimValue(options.claims, [rootClaimName])
          if (rootValue === undefined) {
            continue
          }

          if (nonDisclosableClaims.includes(rootClaimName)) {
            setClaimValue(sdJwtClaims, [rootClaimName], rootValue)
          } else {
            setClaimValue(disclosableClaims, [rootClaimName], rootValue)
          }
        }
      }

      const keyAlg = options?.keyAlg ?? 'ES256'
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
        typ: 'dc+sd-jwt',
      }
      const jwtPayload = {
        iss: credentialIssuer,
        vct,
        iat: Math.floor(Date.now() / 1000),
        ...(options?.subject !== undefined ? { sub: options.subject } : {}),
        ...(holderJwk && Object.keys(holderJwk).length > 0 ? { cnf: { jwk: holderJwk } } : {}),
        ...sdJwtClaims,
      }

      let disclosures: string[] = []
      const hashAlg = 'sha-256'
      if (Object.keys(disclosableClaims).length > 0) {
        disclosures = createDisclosures(hashAlg, disclosableClaims, jwtPayload)
        Object.defineProperty(jwtPayload, '_sd_alg', {
          value: hashAlg,
          enumerable: true,
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
      let sdJwtCredential = `${encode(jwtHeader)}.${encode(jwtPayload)}.${signature}`
      if (disclosures.length > 0) {
        sdJwtCredential = `${encode(jwtHeader)}.${encode(jwtPayload)}.${signature}~${disclosures.join('~')}~`
      }

      return sdJwtCredential
    },
    canHandle(format: CredentialFormats): boolean {
      return format === 'dc+sd-jwt'
    },
  }
}
