import { raise } from '../errors/vcknots.error'
import { ExtensionRegistry } from '../extensions/extension.registry'
import { VcknotsOptions } from '../vcknots.options'
import { accessToken } from './access-token.provider'
import { authzRequestJARKid } from './authorization-request-jar-kid.provider'
import { authzRequestJARX5c } from './authorization-request-jar-x5c.provider'
import { authzSignatureKey } from './authz-signature-key.provider'
import { cnonce } from './cnonce.provider'
import { credentialOffer } from './credential-offer.provider'
import { credentialProofJWT } from './credential-proof-jwt.provider'
import { verifyCredentialJwt } from './verify-credential-jwt-vc-json.provider'
import { dcql } from './dcql.provider'
import { did } from './did-key.provider'
import { holderBinding } from './holder-binding.provider'
import { inMemoryRequestObjectStore } from './in-memory/in-memory-request-object-store.provider'
import { inMemory } from './in-memory/in-memory.provider'
import { issueCredentialJwt } from './issue-credential-jwt-vc-json.provider'
import { issuerSignatureKey } from './issuer-signature-key.provider'
import { jwtSignature } from './jwt-signature.provider'
import { preAuthorizedCode } from './pre-authorized-code.provider'
import { presentationExchange } from './presentation-exchange.provider'
import { Provider } from './provider.types'
import { requestObjectId } from './request-object-id.provider'
import { verifierSignatureKey } from './verifier-signature-key.provider'
import { certificate } from './certificate.provider'
import { transactionData } from './transaction-data.provider'
import { verifyVerifiablePresentation } from './verify-presentation-jwt-vp-json.provider'
import { verifyVerifiablePresentationDcSdJwt } from './verify-presentation-dc-sd-jwt.provider'

type ArrayUnless<P extends Provider> = P['single'] extends true ? P : P[]

export type ProviderMap = {
  [K in Provider['kind']]: ArrayUnless<Extract<Provider, { kind: K }>>
}

type CanHandle<U> = { canHandle(u: U): boolean }

export type SelectableProvider<K extends keyof ProviderMap, U> = ProviderMap[K] extends (infer E)[]
  ? E extends Provider
    ? E['single'] extends false
      ? E extends CanHandle<U>
        ? E
        : never
      : never
    : never
  : never

export type ProviderRegistry = {
  get<K extends keyof ProviderMap>(kind: K): ProviderMap[K]
  select<K extends keyof ProviderMap, T extends SelectableProvider<K, U>, U>(kind: K, u: U): T
}

export type WithProviderRegistry = { providers: ProviderRegistry }

const initializeDefaultProviders = (
  _options?: VcknotsOptions
): NonNullable<VcknotsOptions['providers']> => [
  inMemory(),
  credentialOffer(),
  cnonce(),
  accessToken(),
  preAuthorizedCode(),
  issuerSignatureKey(),
  authzSignatureKey(),
  issueCredentialJwt(),
  did(),
  presentationExchange(),
  dcql(),
  credentialProofJWT(),
  verifyCredentialJwt(),
  jwtSignature(),
  holderBinding(),
  verifierSignatureKey(),
  requestObjectId(),
  inMemoryRequestObjectStore(),
  authzRequestJARKid(),
  authzRequestJARX5c(),
  certificate(),
  transactionData(),
  verifyVerifiablePresentation(),
  verifyVerifiablePresentationDcSdJwt(),
]

export const initializeProviderRegistry = (
  options?: VcknotsOptions,
  extensions?: ExtensionRegistry
): ProviderRegistry => {
  const defaultProviders = initializeDefaultProviders(options)

  const toProviderArray = (acc: Provider[], provider: Provider) =>
    provider.single
      ? acc.filter((it) => it.kind !== provider.kind).concat([provider])
      : acc.concat([provider])

  const toProviderMap = (acc: Partial<ProviderMap>, provider: Provider) => {
    const kind = provider.kind
    if (provider.single) {
      // biome-ignore lint/suspicious/noExplicitAny: FIXME
      acc[kind] = provider as any
    } else {
      const current = acc[provider.kind]
      acc[kind] = current
        ? // biome-ignore lint/suspicious/noExplicitAny: FIXME
          ([provider, ...current] as any)
        : // biome-ignore lint/suspicious/noExplicitAny: FIXME
          ([provider] as any)
    }
    return acc
  }

  const providers = (options?.providers?.flat() ?? [])
    .reduce(toProviderArray, [...defaultProviders.flat()])
    .reduce(toProviderMap, {})

  return {
    get(kind) {
      const provider = providers[kind] ?? raise('PROVIDER_NOT_FOUND', { message: kind })

      for (const it of Array.isArray(provider) ? provider : [provider]) {
        if ('providers' in it) {
          it.providers = this
        }
      }

      if (!extensions) return provider

      if (Array.isArray(provider)) {
        return provider.map((it) => extensions.weave(it)) as typeof provider
      }

      return extensions.weave(provider) as typeof provider
    },

    select(kind, value) {
      const multiples = this.get(kind)
      const candidates = Array.isArray(multiples) ? multiples : [multiples]
      const provider =
        candidates.find((it) => it.canHandle(value)) ??
        raise('PROVIDER_NOT_FOUND', { message: `No provider found which can handle: ${value}` })
      return provider
    },
  }
}

export const withProviderRegistry = {
  providers: {
    get: () => raise('ILLEGAL_STATE'),
    select: () => raise('ILLEGAL_STATE'),
  },
}
