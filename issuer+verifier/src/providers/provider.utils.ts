import { raise } from '../errors/vcknots.error'
import { Provider } from './provider.types'

export type CanHandle<U> = { canHandle(u: U): boolean }

export const selectProvider = <T extends Provider & CanHandle<U>, U>(candidates: T[], u: U): T => {
  const provider =
    candidates.find((it) => it.canHandle(u)) ??
    raise('provider_not_found', { message: `No provider found which can handle: ${u}` })
  return provider
}

