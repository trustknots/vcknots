import { Nonce } from '../../nonce.types'
import { NonceStoreProvider } from '../provider.types'

export const inMemoryNonceStore = (option?: {
  c_nonce_expire_in?: number
}): NonceStoreProvider => {
  type NonceStates = {
    c_nonce: string
    c_nonce_expires_at: number
  }
  const nonceStates = new Map<Nonce, NonceStates>()

  return {
    kind: 'nonce-store-provider',
    name: 'in-memory-nonce-provider',
    single: true,

    async save(nonce): Promise<void> {
      const expiresAt = new Date().getTime() + (option?.c_nonce_expire_in ?? 60 * 5 * 1000) // 5 minutes
      nonceStates.set(nonce, {
        c_nonce: nonce,
        c_nonce_expires_at: expiresAt,
      })
      return
    },

    async validate(nonce): Promise<boolean> {
      const nonceState = nonceStates.get(nonce)
      if (!nonceState) {
        return false
      }
      if (new Date().getTime() > nonceState.c_nonce_expires_at) {
        return false
      }
      return true
    },

    async revoke(nonce): Promise<void> {
      nonceStates.delete(nonce)
      return
    },
  }
}
