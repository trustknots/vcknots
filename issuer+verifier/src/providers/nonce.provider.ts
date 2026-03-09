import { randomUUID } from 'node:crypto'
import { Nonce } from '../nonce.types'
import { NonceProvider } from './provider.types'

export const nonce = (): NonceProvider => {
  return {
    kind: 'nonce-provider',
    name: 'default-nonce-provider',
    single: true,

    async generate(): Promise<Nonce> {
      return Nonce(randomUUID().replaceAll('-', ''))
    },
  }
}
