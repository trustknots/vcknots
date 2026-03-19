import { Nonce } from '../../nonce.types'
import { NonceStoreProvider } from '../provider.types'

export const inMemoryNonceStore = (): NonceStoreProvider => {
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
      const ttlMs = nonce.nonce_expires_in
      if (ttlMs == null) {
        throw new Error('nonce_expires_in is required when saving nonce')
      }
      const expiresAt = new Date().getTime() + ttlMs
      nonceStates.set(nonce.nonce, { nonce, expires_at: expiresAt })
      return
    },

    async validate(nonce): Promise<boolean> {
      const nonceState = nonceStates.get(nonce.nonce)
      if (!nonceState) {
        return false
      }
      if (new Date().getTime() > nonceState.expires_at) {
        nonceStates.delete(nonce.nonce)
        return false
      }
      return true
    },

    async revoke(nonce): Promise<boolean> {
      return nonceStates.delete(nonce.nonce)
    },
  }
}
