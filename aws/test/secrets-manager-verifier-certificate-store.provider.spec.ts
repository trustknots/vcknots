import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { afterEach, describe, it } from 'node:test'
import {
  CreateSecretCommand,
  GetSecretValueCommand,
  InvalidRequestException,
  PutSecretValueCommand,
  ResourceExistsException,
  ResourceNotFoundException,
  SecretsManagerClient,
} from '@aws-sdk/client-secrets-manager'
import { mockClient } from 'aws-sdk-client-mock'
import { Certificate } from '@trustknots/vcknots'
import { VcknotsError } from '@trustknots/vcknots/errors'
import { VerifierClientId } from '@trustknots/vcknots/verifier'
import { VERIFIER_CERTIFICATE_SECRET_PREFIX } from '../src/providers/secrets-manager'
import { secretsManagerVerifierCertificateStore } from '../src/providers/secrets-manager-verifier-certificate-store.provider'

const secretsMock = mockClient(SecretsManagerClient)

const verifier = VerifierClientId('https://verifier.example.com')
const sha256Hex = (value: string) => createHash('sha256').update(value).digest('hex')
const defaultSecretName = `${VERIFIER_CERTIFICATE_SECRET_PREFIX}/${sha256Hex(verifier)}`

const certificate: Certificate = [
  '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----',
  '-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----',
]

const resourceNotFound = () =>
  new ResourceNotFoundException({ message: 'not found', $metadata: {} })
const resourceExists = () =>
  new ResourceExistsException({ message: 'already exists', $metadata: {} })
const invalidRequest = (message: string) => new InvalidRequestException({ message, $metadata: {} })
const accessDenied = () => {
  const error = new Error('access denied')
  error.name = 'AccessDeniedException'
  return error
}

describe('secretsManagerVerifierCertificateStore', () => {
  afterEach(() => {
    secretsMock.reset()
  })

  const createProvider = (secretPrefix?: string) =>
    secretsManagerVerifierCertificateStore({
      client: secretsMock as unknown as SecretsManagerClient,
      secretPrefix,
    })

  it('should have correct provider metadata', () => {
    const provider = createProvider()

    assert.equal(provider.kind, 'verifier-certificate-store-provider')
    assert.equal(provider.name, 'secrets-manager-verifier-certificate-store-provider')
    assert.equal(provider.single, true)
  })

  it('should save a certificate as a new secret under the default prefix', async () => {
    secretsMock.on(CreateSecretCommand).resolves({})

    await createProvider().save(verifier, certificate)

    const calls = secretsMock.commandCalls(CreateSecretCommand)
    assert.equal(calls.length, 1)
    assert.equal(calls[0].args[0].input.Name, defaultSecretName)
    // Stored as PEM: only fetch() strips the armor.
    assert.deepEqual(JSON.parse(calls[0].args[0].input.SecretString ?? ''), certificate)
    assert.equal(secretsMock.commandCalls(PutSecretValueCommand).length, 0)
  })

  it('should use a custom secret prefix when provided', async () => {
    secretsMock.on(CreateSecretCommand).resolves({})

    await createProvider('custom/prefix').save(verifier, certificate)

    const calls = secretsMock.commandCalls(CreateSecretCommand)
    assert.equal(calls[0].args[0].input.Name, `custom/prefix/${sha256Hex(verifier)}`)
  })

  it('should derive distinct secret names per verifier', async () => {
    secretsMock.on(CreateSecretCommand).resolves({})
    const other = VerifierClientId('https://other-verifier.example.com')

    const provider = createProvider()
    await provider.save(verifier, certificate)
    await provider.save(other, certificate)

    const [first, second] = secretsMock.commandCalls(CreateSecretCommand)
    assert.notEqual(first.args[0].input.Name, second.args[0].input.Name)
    assert.equal(
      second.args[0].input.Name,
      `${VERIFIER_CERTIFICATE_SECRET_PREFIX}/${sha256Hex(other)}`
    )
  })

  it('should add a new secret version when the secret already exists', async () => {
    secretsMock.on(CreateSecretCommand).rejects(resourceExists())
    secretsMock.on(PutSecretValueCommand).resolves({})

    await createProvider().save(verifier, certificate)

    const calls = secretsMock.commandCalls(PutSecretValueCommand)
    assert.equal(calls.length, 1)
    assert.equal(calls[0].args[0].input.SecretId, defaultSecretName)
    assert.deepEqual(JSON.parse(calls[0].args[0].input.SecretString ?? ''), certificate)
  })

  it('should reject a certificate that fails schema validation', async () => {
    const provider = createProvider()

    await assert.rejects(() => provider.save(verifier, ['not-a-pem'] as unknown as Certificate))
    assert.equal(secretsMock.commandCalls(CreateSecretCommand).length, 0)
  })

  it('should raise an actionable error when the secret is scheduled for deletion', async () => {
    secretsMock
      .on(CreateSecretCommand)
      .rejects(
        invalidRequest('You cannot create this secret because it is scheduled for deletion.')
      )

    await assert.rejects(
      () => createProvider().save(verifier, certificate),
      (error: VcknotsError) => {
        assert.equal(error.name, 'internal_server_error')
        assert.match(error.message, /may be scheduled for deletion/)
        assert.match(error.message, /ForceDeleteWithoutRecovery/)
        // The hedged wording keeps the original cause visible, since InvalidRequestException
        // also covers state conflicts unrelated to deletion.
        assert.match(error.message, /scheduled for deletion\.$/)
        return true
      }
    )
    assert.equal(secretsMock.commandCalls(PutSecretValueCommand).length, 0)
  })

  it('should raise when creating the secret fails for an unexpected reason', async () => {
    secretsMock.on(CreateSecretCommand).rejects(accessDenied())

    await assert.rejects(
      () => createProvider().save(verifier, certificate),
      (error: VcknotsError) => {
        assert.equal(error.name, 'internal_server_error')
        assert.match(error.message, /Failed to create verifier certificate secret/)
        return true
      }
    )
    assert.equal(secretsMock.commandCalls(PutSecretValueCommand).length, 0)
  })

  it('should raise when storing a new secret version fails', async () => {
    secretsMock.on(CreateSecretCommand).rejects(resourceExists())
    secretsMock.on(PutSecretValueCommand).rejects(accessDenied())

    await assert.rejects(
      () => createProvider().save(verifier, certificate),
      (error: VcknotsError) => {
        assert.equal(error.name, 'internal_server_error')
        assert.match(error.message, /Failed to store verifier certificate/)
        return true
      }
    )
  })

  it('should fetch a certificate as bare base64 DER', async () => {
    secretsMock.on(GetSecretValueCommand).resolves({ SecretString: JSON.stringify(certificate) })

    const fetched = await createProvider().fetch(verifier)

    assert.deepEqual(fetched, ['MIIB', 'MIIC'])
    const calls = secretsMock.commandCalls(GetSecretValueCommand)
    assert.equal(calls[0].args[0].input.SecretId, defaultSecretName)
  })

  it('should read a certificate stored as SecretBinary', async () => {
    secretsMock.on(GetSecretValueCommand).resolves({
      SecretBinary: new TextEncoder().encode(JSON.stringify(certificate)),
    })

    const fetched = await createProvider().fetch(verifier)

    assert.deepEqual(fetched, ['MIIB', 'MIIC'])
  })

  it('should return an empty certificate for an unregistered verifier', async () => {
    secretsMock.on(GetSecretValueCommand).rejects(resourceNotFound())

    const fetched = await createProvider().fetch(verifier)

    assert.deepEqual(fetched, [])
  })

  it('should return an empty certificate when the secret holds no value', async () => {
    secretsMock.on(GetSecretValueCommand).resolves({})

    const fetched = await createProvider().fetch(verifier)

    assert.deepEqual(fetched, [])
  })

  it('should raise when the stored value is not a valid certificate', async () => {
    secretsMock.on(GetSecretValueCommand).resolves({ SecretString: '{"not":"a certificate"}' })

    await assert.rejects(
      () => createProvider().fetch(verifier),
      (error: VcknotsError) => {
        assert.equal(error.name, 'internal_server_error')
        assert.match(error.message, /Failed to load verifier certificate/)
        return true
      }
    )
  })

  it('should raise when reading the secret fails for an unexpected reason', async () => {
    secretsMock.on(GetSecretValueCommand).rejects(accessDenied())

    await assert.rejects(
      () => createProvider().fetch(verifier),
      (error: VcknotsError) => {
        assert.equal(error.name, 'internal_server_error')
        assert.match(error.message, /Failed to load verifier certificate/)
        return true
      }
    )
  })

  it('should round-trip a certificate through save and fetch', async () => {
    secretsMock.on(CreateSecretCommand).resolves({})

    const provider = createProvider()
    await provider.save(verifier, certificate)

    const stored = secretsMock.commandCalls(CreateSecretCommand)[0].args[0].input.SecretString
    secretsMock.on(GetSecretValueCommand).resolves({ SecretString: stored })

    assert.deepEqual(await provider.fetch(verifier), ['MIIB', 'MIIC'])
  })
})
