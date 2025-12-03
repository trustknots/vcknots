import assert from 'node:assert/strict'
import { beforeEach, describe, it } from 'node:test'
import { ClientId } from '../../../src/client-id.types'
import { inMemoryVerifierCertificateStore } from '../../../src/providers/in-memory/in-memory-verifier-certificate-store.provider'
import { Certificate } from '../../../src/signature-key.types'

describe('inMemoryVerifierCertificateStore', () => {
  let store: ReturnType<typeof inMemoryVerifierCertificateStore>
  const verifier = ClientId('https://verifier.example.com')
  const cert: Certificate = [
    '-----BEGIN CERTIFICATE-----\r\nMII...',
    '-----END CERTIFICATE-----\r\n',
  ]
  const cleanedCert = ['MII...', '']

  beforeEach(() => {
    store = inMemoryVerifierCertificateStore()
  })

  it('should save and fetch a certificate for a verifier', async () => {
    await store.save(verifier, cert)
    const fetched = await store.fetch(verifier)
    assert.deepStrictEqual(fetched, cleanedCert)
  })

  it('should return an empty array if no certificate is saved', async () => {
    const fetched = await store.fetch(ClientId('https://unknown.example.com'))
    assert.deepStrictEqual(fetched, [])
  })

  it('should overwrite an existing certificate', async () => {
    const newCert: Certificate = [
      '-----BEGIN CERTIFICATE-----\r\nNEW...',
      '-----END CERTIFICATE-----\r\n',
    ]
    const newCleanedCert = ['NEW...', '']
    await store.save(verifier, cert)
    await store.save(verifier, newCert)
    const fetched = await store.fetch(verifier)
    assert.deepStrictEqual(fetched, newCleanedCert)
  })
})
