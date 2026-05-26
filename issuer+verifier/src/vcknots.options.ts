import { Extension } from './extensions/extension.types'
import { Provider } from './providers/provider.types'

type Providers = (Provider | Provider[])[]
type Extensions = (Extension | Extension[])[]
export type DPoPMode = 'off' | 'optional' | 'required'

export type DPoPOptions = {
  mode?: DPoPMode
}

export type SenderConstraintMethod = 'none' | 'dpop' | 'mtls'

export type SenderConstrainedAccessTokenOptions = {
  method?: SenderConstraintMethod
  dpop?: DPoPOptions
}

export type OAuthOptions = {
  senderConstrainedAccessToken?: SenderConstrainedAccessTokenOptions
}

export type VcknotsOptions = {
  providers?: Providers
  extensions?: Extensions
  debug?: boolean
  oauth?: OAuthOptions
}

export const resolveDpopMode = (options?: Pick<VcknotsOptions, 'oauth'>): DPoPMode =>
  options?.oauth?.senderConstrainedAccessToken?.dpop?.mode ?? 'off'
