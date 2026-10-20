import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { afterEach, describe, it } from 'node:test'
import { DynamoDBDocumentClient, PutCommand } from '@aws-sdk/lib-dynamodb'
import { mockClient } from 'aws-sdk-client-mock'
import { dynamodbOAuthClientAssertionJtiStore } from '../src/providers/dynamodb-oauth-client-assertion-jti-store.provider'

const TABLE_NAME = 'OAuthClientAssertionJtisTable'
const DEFAULT_TTL_MS = 5 * 60 * 1000
const ddbMock = mockClient(DynamoDBDocumentClient)

const conditionalCheckFailed = () =>
  Object.assign(new Error('The conditional request failed'), {
    name: 'ConditionalCheckFailedException',
  })

const expectedId = (clientId: string, jti: string) =>
  createHash('sha256')
    .update(JSON.stringify([clientId, jti]))
    .digest('hex')

describe('dynamodbOAuthClientAssertionJtiStore', () => {
  afterEach(() => {
    ddbMock.reset()
  })

  const createProvider = (expiresIn?: number) =>
    dynamodbOAuthClientAssertionJtiStore({
      client: ddbMock as unknown as DynamoDBDocumentClient,
      tableName: TABLE_NAME,
      expiresIn,
    })

  const putInput = () => {
    const input = ddbMock.commandCalls(PutCommand)[0]?.args[0].input
    assert.ok(input)
    return input
  }

  it('should have correct provider metadata', () => {
    const provider = createProvider()
    assert.equal(provider.kind, 'oauth-client-assertion-jti-store-provider')
    assert.equal(provider.name, 'dynamodb-oauth-client-assertion-jti-store-provider')
    assert.equal(provider.single, true)
  })

  it('should save an unused jti with a conditional put and return true', async () => {
    ddbMock.on(PutCommand).resolves({})
    const before = Date.now()

    const result = await createProvider().saveIfAbsent('client-1', 'jti-1')

    const after = Date.now()
    assert.equal(result, true)
    const input = putInput()
    assert.equal(input.TableName, TABLE_NAME)
    assert.equal(input.ConditionExpression, 'attribute_not_exists(id) OR expires_at < :now')
    const now = input.ExpressionAttributeValues?.[':now'] as number
    assert.ok(now >= before && now <= after)
    assert.equal(input.Item?.created_at, now)
  })

  it('should return false when the jti is already stored and unexpired', async () => {
    ddbMock.on(PutCommand).rejects(conditionalCheckFailed())

    const result = await createProvider().saveIfAbsent('client-1', 'jti-1')

    assert.equal(result, false)
  })

  it('should rethrow errors other than a failed condition', async () => {
    ddbMock.on(PutCommand).rejects(new Error('DynamoDB unavailable'))

    await assert.rejects(
      () => createProvider().saveIfAbsent('client-1', 'jti-1'),
      /DynamoDB unavailable/
    )
  })

  it('should store replay entries under a hashed id with the replay key fields', async () => {
    ddbMock.on(PutCommand).resolves({})

    await createProvider().saveIfAbsent('https://wallet.example.com', 'jti/with:special')

    const item = putInput().Item
    assert.equal(item?.id, expectedId('https://wallet.example.com', 'jti/with:special'))
    assert.match(item?.id as string, /^[0-9a-f]{64}$/)
    assert.equal(item?.client_id, 'https://wallet.example.com')
    assert.equal(item?.jti, 'jti/with:special')
  })

  it('should treat different clients or jtis as different replay keys', async () => {
    ddbMock.on(PutCommand).resolves({})
    const provider = createProvider()

    await provider.saveIfAbsent('client-1', 'jti-1')
    await provider.saveIfAbsent('client-2', 'jti-1')
    await provider.saveIfAbsent('client-1', 'jti-2')

    const ids = ddbMock.commandCalls(PutCommand).map((call) => call.args[0].input.Item?.id)
    assert.equal(new Set(ids).size, 3)
  })

  it('should avoid delimiter collisions when building replay keys', async () => {
    ddbMock.on(PutCommand).resolves({})
    const provider = createProvider()

    await provider.saveIfAbsent('client:a', 'b')
    await provider.saveIfAbsent('client', 'a:b')

    const ids = ddbMock.commandCalls(PutCommand).map((call) => call.args[0].input.Item?.id)
    assert.notEqual(ids[0], ids[1])
  })

  it('should default to a 5 minute retention with epoch-ms expires_at and epoch-seconds ttl', async () => {
    ddbMock.on(PutCommand).resolves({})

    await createProvider().saveIfAbsent('client-1', 'jti-1')

    const input = putInput()
    const now = input.ExpressionAttributeValues?.[':now'] as number
    assert.equal(input.Item?.expires_at, now + DEFAULT_TTL_MS)
    assert.equal(input.Item?.ttl, Math.ceil((now + DEFAULT_TTL_MS) / 1000))
  })

  it('should round ttl up so DynamoDB TTL never deletes before expires_at', async () => {
    ddbMock.on(PutCommand).resolves({})

    await createProvider().saveIfAbsent('client-1', 'jti-1', { ttlMs: 1 })

    const item = putInput().Item
    assert.ok((item?.ttl as number) * 1000 >= (item?.expires_at as number))
  })

  it('should use provider expiresIn when no per-call ttlMs is given', async () => {
    ddbMock.on(PutCommand).resolves({})

    await createProvider(60_000).saveIfAbsent('client-1', 'jti-1')

    const input = putInput()
    const now = input.ExpressionAttributeValues?.[':now'] as number
    assert.equal(input.Item?.expires_at, now + 60_000)
  })

  it('should prefer per-call ttlMs over provider expiresIn', async () => {
    ddbMock.on(PutCommand).resolves({})

    await createProvider(60_000).saveIfAbsent('client-1', 'jti-1', { ttlMs: 1_000 })

    const input = putInput()
    const now = input.ExpressionAttributeValues?.[':now'] as number
    assert.equal(input.Item?.expires_at, now + 1_000)
  })

  it('should reject a non-finite ttlMs without writing', async () => {
    const provider = createProvider()

    await assert.rejects(
      () => provider.saveIfAbsent('client-1', 'jti-1', { ttlMs: Number.NaN }),
      /ttlMs must be a finite number/
    )
    assert.equal(ddbMock.commandCalls(PutCommand).length, 0)
  })
})
