import { ExtensionRegistry, initializeExtensionRegistry } from './extensions/extension.registry'
import { ProviderRegistry, initializeProviderRegistry } from './providers/provider.registry'
import { VcknotsOptions } from './vcknots.options'

export type VcknotsContext = {
  options?: VcknotsOptions
  providers: ProviderRegistry
  extensions: ExtensionRegistry
}

export const initializeContext = (options?: VcknotsOptions): VcknotsContext => {
  const extensions = initializeExtensionRegistry(options)
  const providers = initializeProviderRegistry(options, extensions)

  return {
    options,
    providers,
    extensions,
  }
}
