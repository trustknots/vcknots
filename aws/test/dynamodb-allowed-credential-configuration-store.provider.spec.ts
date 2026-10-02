import assert from 'node:assert/strict'
import { afterEach, describe, it, mock } from 'node:test'
import {
  DeleteCommand,
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
} from '@aws-sdk/lib-dynamodb'
import { CredentialConfigurationId } from '@trustknots/vcknots'
import { mockClient } from 'aws-sdk-client-mock'
import { dynamodbAllowedCredentialConfigurationStore } from '../src/providers/dynamodb-allowed-credential-configuration-store.provider'

const TABLE_NAME = 'AllowedCredentialConfigurationsTable'
const ddbMock = mockClient(DynamoDBDocumentClient)

describe('dynamodbAllowedCredentialConfigurationStore', () => {
  const configurations: CredentialConfigurationId[] = [
    CredentialConfigurationId('University_Degree'),
  ]

  afterEach(() => {
    ddbMock.reset()
    mock.timers.reset()
  })

  const createProvider = (expiresIn?: number) =>
    dynamodbAllowedCredentialConfigurationStore({
      client: ddbMock as unknown as DynamoDBDocumentClient,
      tableName: TABLE_NAME,
      expiresIn,
    })

  const savedItem = () => ddbMock.commandCalls(PutCommand)[0]?.args[0].input.Item

  /** Saves at a fixed clock and returns the TTL (in seconds) derived from expires_at. */
  const savedTtlSec = async (
    provider: ReturnType<typeof createProvider>,
    ttl?: number
  ): Promise<number> => {
    mock.timers.enable({ apis: ['Date'], now: 1_000_000 })
    ddbMock.on(PutCommand).resolves({})
    await provider.save('ttl-check', configurations, ttl)
    return (savedItem()?.expires_at - 1_000_000) / 1000
  }

  it('should have correct provider metadata', () => {
    const provider = createProvider()
    assert.equal(provider.kind, 'allowed-credential-configuration-store-provider')
    assert.equal(provider.name, 'dynamodb-allowed-credential-configuration-store-provider')
    assert.equal(provider.single, true)
  })

  it('should save with epoch-ms expires_at, epoch-seconds ttl and created_at', async () => {
    mock.timers.enable({ apis: ['Date'], now: 1_000_500 })
    ddbMock.on(PutCommand).resolves({})

    const provider = createProvider()
    await provider.save('test-access-token-hash', configurations, 60)

    const putCall = ddbMock.commandCalls(PutCommand)[0]
    assert.equal(putCall?.args[0].input.TableName, TABLE_NAME)
    assert.deepEqual(putCall?.args[0].input.Item, {
      id: 'test-access-token-hash',
      credential_configuration_ids: configurations,
      expires_at: 1_060_500,
      // Rounded up so TTL never fires before the real (ms) expiry.
      ttl: 1061,
      created_at: 1_000_500,
    })
  })

  it('should use the per-save ttl over expiresIn', async () => {
    assert.equal(await savedTtlSec(createProvider(120), 60), 60)
  })

  it('should use expiresIn when ttl is not specified', async () => {
    assert.equal(await savedTtlSec(createProvider(120)), 120)
  })

  it('should use default ttl of 300 seconds when neither ttl nor expiresIn is specified', async () => {
    assert.equal(await savedTtlSec(createProvider()), 300)
  })

  it('should fall back to default ttl for invalid ttl', async () => {
    assert.equal(await savedTtlSec(createProvider(), Number.NaN), 300)
  })

  it('should fall back to default ttl for non-positive ttl', async () => {
    assert.equal(await savedTtlSec(createProvider(), 0), 300)
  })

  it('should floor fractional ttl', async () => {
    assert.equal(await savedTtlSec(createProvider(), 1.5), 1)
  })

  it('should fall back to default ttl when fractional ttl floors to zero', async () => {
    assert.equal(await savedTtlSec(createProvider(), 0.5), 300)
  })

  it('fetch should return credential configuration ids for a valid entry', async () => {
    ddbMock.on(GetCommand).resolves({
      Item: {
        id: 'test-access-token-hash',
        credential_configuration_ids: configurations,
        expires_at: Date.now() + 300 * 1000,
      },
    })

    const provider = createProvider()
    assert.deepStrictEqual(await provider.fetch('test-access-token-hash'), configurations)
    const getCall = ddbMock.commandCalls(GetCommand)[0]
    assert.equal(getCall?.args[0].input.TableName, TABLE_NAME)
    assert.deepEqual(getCall?.args[0].input.Key, { id: 'test-access-token-hash' })
    assert.equal(getCall?.args[0].input.ConsistentRead, true)
    assert.equal(ddbMock.commandCalls(DeleteCommand).length, 0)
  })

  it('fetch should return null for an unknown access token hash', async () => {
    ddbMock.on(GetCommand).resolves({})

    const provider = createProvider()
    assert.equal(await provider.fetch('unknown-access-token-hash'), null)
  })

  it('fetch should treat the exact expiry boundary as still valid', async () => {
    mock.timers.enable({ apis: ['Date'], now: 1_000_000 })
    ddbMock.on(GetCommand).resolves({
      Item: { id: 'boundary', credential_configuration_ids: configurations, expires_at: 1_000_000 },
    })

    const provider = createProvider()
    assert.deepStrictEqual(await provider.fetch('boundary'), configurations)
  })

  it('fetch should return null and delete an expired entry', async () => {
    ddbMock.on(GetCommand).resolves({
      Item: {
        id: 'expired-access-token-hash',
        credential_configuration_ids: configurations,
        expires_at: Date.now() - 1000,
      },
    })
    ddbMock.on(DeleteCommand).resolves({})

    const provider = createProvider()
    assert.equal(await provider.fetch('expired-access-token-hash'), null)

    // Match the Firestore provider: expired entries are proactively deleted, not left to TTL.
    const deleteCall = ddbMock.commandCalls(DeleteCommand)[0]
    assert.equal(deleteCall?.args[0].input.TableName, TABLE_NAME)
    assert.deepEqual(deleteCall?.args[0].input.Key, { id: 'expired-access-token-hash' })
  })

  it('fetch should treat a missing expires_at as expired', async () => {
    ddbMock.on(GetCommand).resolves({
      Item: { id: 'no-expiry', credential_configuration_ids: configurations },
    })
    ddbMock.on(DeleteCommand).resolves({})

    const provider = createProvider()
    assert.equal(await provider.fetch('no-expiry'), null)
    assert.equal(ddbMock.commandCalls(DeleteCommand).length, 1)
  })

  it('delete should remove the entry by access token hash', async () => {
    ddbMock.on(DeleteCommand).resolves({})

    const provider = createProvider()
    await provider.delete('delete-me')

    const deleteCall = ddbMock.commandCalls(DeleteCommand)[0]
    assert.equal(deleteCall?.args[0].input.TableName, TABLE_NAME)
    assert.deepEqual(deleteCall?.args[0].input.Key, { id: 'delete-me' })
  })
})
