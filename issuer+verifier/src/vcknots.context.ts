import { ExtensionRegistry, initializeExtensionRegistry } from './extensions/extension.registry'
import { ProviderRegistry, initializeProviderRegistry } from './providers/provider.registry'
import { VcknotsOptions } from './vcknots.options'

export type VcknotsContext = {
  options?: VcknotsOptions
  providers: ProviderRegistry
  extensions: ExtensionRegistry
}

export const initializeContext = (options?: VcknotsOptions): VcknotsContext => {
  const resolvedOptions = resolveVcknotsOptions(options)
  const extensions = initializeExtensionRegistry(resolvedOptions)
  const providers = initializeProviderRegistry(resolvedOptions, extensions)

  return {
    options: resolvedOptions,
    providers,
    extensions,
  }
}

type ResolvedVcknotsOptions = Omit<VcknotsOptions, 'debug' | 'allowInsecureHttp'> & {
  debug: boolean
  allowInsecureHttp: boolean
}

const resolveVcknotsOptions = (options?: VcknotsOptions): ResolvedVcknotsOptions => {
  const isProduction = process.env.NODE_ENV === 'production'
  const debug = !isProduction && (options?.debug || process.env.VCKNOTS_DEBUG === 'true')
  const allowInsecureHttp =
    !isProduction &&
    (options?.allowInsecureHttp || process.env.VCKNOTS_ALLOW_INSECURE_HTTP === 'true')

  return {
    ...options,
    debug: debug,
    allowInsecureHttp: allowInsecureHttp,
  }
}
