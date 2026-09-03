import { Nonce } from '../../nonce.types'
import { NonceStoreProvider } from '../provider.types'

export const inMemoryNonceStore = (): NonceStoreProvider => {
  type NonceState = {
    nonce: Nonce
    expires_at: number
  }
  const nonceStates = new Map<string, NonceState>()
  const now = () => new Date().getTime()

  const getValidNonceState = (nonce: Nonce): NonceState | null => {
    const nonceState = nonceStates.get(nonce.nonce)
    if (!nonceState) {
      return null
    }
    if (now() > nonceState.expires_at) {
      nonceStates.delete(nonce.nonce)
      return null
    }
    return nonceState
  }

  return {
    kind: 'nonce-store-provider',
    name: 'in-memory-nonce-provider',
    single: true,

    async save(nonce): Promise<void> {
      const ttlMs = nonce.nonce_expires_in
      if (ttlMs == null) {
        throw new Error('nonce_expires_in is required when saving nonce')
      }
      const expiresAt = now() + ttlMs
      nonceStates.set(nonce.nonce, { nonce, expires_at: expiresAt })
      return
    },

    async validate(nonce): Promise<boolean> {
      return getValidNonceState(nonce) !== null
    },

    async revoke(nonce): Promise<boolean> {
      return nonceStates.delete(nonce.nonce)
    },

    async consume(nonce): Promise<boolean> {
      const nonceState = getValidNonceState(nonce)
      if (!nonceState) {
        return false
      }
      return nonceStates.delete(nonce.nonce)
    },
  }
}
