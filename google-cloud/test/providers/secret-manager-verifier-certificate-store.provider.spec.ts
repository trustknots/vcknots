import assert from 'node:assert/strict'
import { afterEach, describe, it } from 'node:test'
import { createHash } from 'node:crypto'
import { Certificate, ClientId } from '@trustknots/vcknots'
import { VcknotsError } from '@trustknots/vcknots/errors'
import { secretManagerVerifierCertificateStoreProvider } from '../../src/providers/secret-manager-verifier-certificate-store.provider'
import { createSecretManagerTestMock } from './secret-manager-test-mock'

describe('secretManagerVerifierCertificateStoreProvider', () => {
  const md5 = (value: string) => createHash('md5').update(value).digest('base64url')
  const verifier = ClientId('https://verifier.example.com')
  const certificate: Certificate = [
    '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----',
    '-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----',
  ]

  const originalProjectId = process.env.GOOGLE_CLOUD_PROJECT_ID

  afterEach(() => {
    if (originalProjectId === undefined) {
      Reflect.deleteProperty(process.env, 'GOOGLE_CLOUD_PROJECT_ID')
    } else {
      process.env.GOOGLE_CLOUD_PROJECT_ID = originalProjectId
    }
  })

  it('should have correct provider metadata', () => {
    const { client } = createSecretManagerTestMock()
    const provider = secretManagerVerifierCertificateStoreProvider({
      client,
      projectId: 'project-123',
    })

    assert.equal(provider.kind, 'verifier-certificate-store-provider')
    assert.equal(provider.name, 'secret-manager-verifier-certificate-store-provider')
    assert.equal(provider.single, true)
  })

  it('should save and fetch a verifier certificate', async () => {
    const { client } = createSecretManagerTestMock()
    const provider = secretManagerVerifierCertificateStoreProvider({
      client,
      projectId: 'project-123',
    })

    await provider.save(verifier, certificate)
    const fetched = await provider.fetch(verifier)

    assert.deepEqual(fetched, ['MIIB', 'MIIC'])
  })

  it('should use the default secret prefix', async () => {
    const { client, secrets } = createSecretManagerTestMock()
    const provider = secretManagerVerifierCertificateStoreProvider({
      client,
      projectId: 'project-123',
    })
    const expectedSecretName = `projects/project-123/secrets/vcknots-verifier-certificate-${md5(verifier)}`

    await provider.save(verifier, certificate)

    assert.ok(secrets.has(expectedSecretName))
  })

  it('should use a custom secret prefix', async () => {
    const { client, secrets } = createSecretManagerTestMock()
    const provider = secretManagerVerifierCertificateStoreProvider({
      client,
      projectId: 'project-123',
      secretPrefix: 'custom-prefix',
    })
    const expectedSecretName = `projects/project-123/secrets/custom-prefix-${md5(verifier)}`

    await provider.save(verifier, certificate)

    assert.ok(secrets.has(expectedSecretName))
  })

  it('should return an empty array for an unknown verifier', async () => {
    const { client } = createSecretManagerTestMock()
    const provider = secretManagerVerifierCertificateStoreProvider({
      client,
      projectId: 'project-123',
    })

    const fetched = await provider.fetch(ClientId('https://unknown.example.com'))

    assert.deepEqual(fetched, [])
  })

  it('should accept string payloads from secret manager', async () => {
    const { client, secrets } = createSecretManagerTestMock()
    const provider = secretManagerVerifierCertificateStoreProvider({
      client,
      projectId: 'project-123',
    })
    const secretName = `projects/project-123/secrets/vcknots-verifier-certificate-${md5(verifier)}`

    secrets.set(secretName, {
      versions: [JSON.stringify(certificate) as unknown as Uint8Array],
    })

    const fetched = await provider.fetch(verifier)

    assert.deepEqual(fetched, ['MIIB', 'MIIC'])
  })

  it('should overwrite the latest certificate version', async () => {
    const { client, calls } = createSecretManagerTestMock()
    const provider = secretManagerVerifierCertificateStoreProvider({
      client,
      projectId: 'project-123',
    })
    const nextCertificate: Certificate = [
      '-----BEGIN CERTIFICATE-----\nMIID\n-----END CERTIFICATE-----',
    ]

    await provider.save(verifier, certificate)
    await provider.save(verifier, nextCertificate)

    const fetched = await provider.fetch(verifier)
    assert.deepEqual(fetched, ['MIID'])
    assert.equal(calls.createSecret.length, 2)
    assert.equal(calls.addSecretVersion.length, 2)
  })

  it('should use GOOGLE_CLOUD_PROJECT_ID when projectId option is omitted', async () => {
    process.env.GOOGLE_CLOUD_PROJECT_ID = 'env-project'
    const { client, secrets } = createSecretManagerTestMock()
    const provider = secretManagerVerifierCertificateStoreProvider({ client })
    const expectedSecretName = `projects/env-project/secrets/vcknots-verifier-certificate-${md5(verifier)}`

    await provider.save(verifier, certificate)

    assert.ok(secrets.has(expectedSecretName))
  })

  it('should wrap unexpected fetch errors as VcknotsError', async () => {
    const { client } = createSecretManagerTestMock()
    client.accessSecretVersion = async () => {
      throw new Error('permission denied')
    }

    const provider = secretManagerVerifierCertificateStoreProvider({
      client,
      projectId: 'project-123',
    })

    await assert.rejects(provider.fetch(verifier), (error: unknown) => {
      assert.ok(error instanceof VcknotsError)
      assert.equal(error.name, 'INTERNAL_SERVER_ERROR')
      assert.equal(error.message, 'Failed to load verifier certificate from Secret Manager.')
      return true
    })
  })

  it('should wrap unexpected save errors as VcknotsError', async () => {
    const { client } = createSecretManagerTestMock()
    client.addSecretVersion = async () => {
      throw new Error('permission denied')
    }

    const provider = secretManagerVerifierCertificateStoreProvider({
      client,
      projectId: 'project-123',
    })

    await assert.rejects(provider.save(verifier, certificate), (error: unknown) => {
      assert.ok(error instanceof VcknotsError)
      assert.equal(error.name, 'INTERNAL_SERVER_ERROR')
      assert.equal(error.message, 'Failed to store verifier certificate in Secret Manager.')
      return true
    })
  })

  it('should throw when client is missing', () => {
    assert.throws(
      () => secretManagerVerifierCertificateStoreProvider({ projectId: 'project-123' }),
      /Missing Secret Manager client/
    )
  })

  it('should throw when projectId is missing', () => {
    Reflect.deleteProperty(process.env, 'GOOGLE_CLOUD_PROJECT_ID')
    const { client } = createSecretManagerTestMock()

    assert.throws(
      () => secretManagerVerifierCertificateStoreProvider({ client }),
      /Missing projectId/
    )
  })
})
