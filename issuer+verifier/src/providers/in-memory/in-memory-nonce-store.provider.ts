import { Nonce } from '../../nonce.types'
import { NonceStoreProvider } from '../provider.types'

export const inMemoryNonceStore = (option?: {
  c_nonce_expire_in?: number
}): NonceStoreProvider => {
  type NonceState = {
    nonce: Nonce
    expires_at: number
  }
  const nonceStates = new Map<string, NonceState>()

  return {
    kind: 'nonce-store-provider',
    name: 'in-memory-nonce-provider',
    single: true,

    async save(nonce): Promise<void> {
      const expiresAt =
        new Date().getTime() +
        (nonce.nonce_expires_in ?? option?.c_nonce_expire_in ?? 60 * 5 * 1000)
      nonceStates.set(nonce.nonce, { nonce, expires_at: expiresAt })
      return
    },

    async validate(nonce): Promise<boolean> {
      const nonceState = nonceStates.get(nonce.nonce)
      if (!nonceState) {
        return false
      }
      if (new Date().getTime() > nonceState.expires_at) {
        return false
      }
      return true
    },

    async revoke(nonce): Promise<void> {
      nonceStates.delete(nonce.nonce)
      return
    },
  }
}
