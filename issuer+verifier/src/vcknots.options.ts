import { Extension } from './extensions/extension.types'
import { Provider } from './providers/provider.types'

type Providers = (Provider | Provider[])[]
type Extensions = (Extension | Extension[])[]

export type VcknotsOptions = {
  providers?: Providers
  extensions?: Extensions
  debug?: boolean
}
