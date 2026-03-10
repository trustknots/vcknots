import { randomUUID } from 'node:crypto'
import { Nonce } from '../nonce.types'
import { NonceProvider } from './provider.types'

const DEFAULT_NONCE_EXPIRES_IN_MS = 60 * 5 * 1000 // 5 minutes

export const nonce = (): NonceProvider => {
  return {
    kind: 'nonce-provider',
    name: 'default-nonce-provider',
    single: true,

    async generate(options?: { nonce_expires_in: number }): Promise<Nonce> {
      return Nonce({
        nonce: randomUUID().replaceAll('-', ''),
        nonce_expires_in: options?.nonce_expires_in ?? DEFAULT_NONCE_EXPIRES_IN_MS,
      })
    },
  }
}
