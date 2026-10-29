import assert from 'node:assert/strict'
import { afterEach, describe, it } from 'node:test'
import { DeleteCommand, DynamoDBDocumentClient, GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb'
import { mockClient } from 'aws-sdk-client-mock'
import { TransactionId, TransactionRecord } from '@trustknots/vcknots'
import { dynamodbVerifierTransactionDataStore } from '../src/providers/dynamodb-verifier-transaction-store.provider'

const TABLE_NAME = 'VerifierTransactionsTable'
const ddbMock = mockClient(DynamoDBDocumentClient)

describe('dynamodbVerifierTransactionDataStore', () => {
  const transactionId = TransactionId('test-transaction-id')
  const dcqlQuery = {
    dcql_query: {
      credentials: [
        {
          id: 'test-cred',
          format: 'jwt_vc_json',
          meta: { type_values: [['VerifiableCredential']] },
          claims: [{ path: ['vc', 'credentialSubject', 'name'] }],
        },
      ],
    },
  }
  const transactionRecord = TransactionRecord({
    dcqlQuery,
    clientId: 'redirect_uri:https://example.com',
    verifierId: 'https://example.com',
    state: 'test-state',
    nonce: 'test-nonce',
  })
  const transactionRecordWithoutState = TransactionRecord({
    dcqlQuery,
    clientId: 'redirect_uri:https://example.com',
    verifierId: 'https://example.com',
    nonce: 'test-nonce',
  })

  afterEach(() => {
    ddbMock.reset()
  })

  const createProvider = (expiresIn?: number) =>
    dynamodbVerifierTransactionDataStore({
      client: ddbMock as unknown as DynamoDBDocumentClient,
      tableName: TABLE_NAME,
      ...(expiresIn !== undefined && { expiresIn }),
    })

  it('should have correct provider metadata', () => {
    const provider = createProvider()
    assert.equal(provider.kind, 'verifier-transaction-store-provider')
    assert.equal(provider.name, 'dynamodb-verifier-transaction-store-provider')
    assert.equal(provider.single, true)
  })

  it('should save and fetch a transaction', async () => {
    const futureExpiry = Date.now() + 300 * 1000
    ddbMock.on(PutCommand).resolves({})
    ddbMock.on(GetCommand).resolves({
      Item: { id: transactionId, ...transactionRecord, expires_at: futureExpiry },
    })

    const provider = createProvider()
    await provider.save(transactionId, transactionRecord)
    const fetched = await provider.fetch(transactionId)

    assert.deepEqual(fetched, {
      transaction_id: transactionId,
      transaction_data_expires_at: futureExpiry,
      ...transactionRecord,
    })
    assert.equal(ddbMock.commandCalls(PutCommand).length, 1)
    assert.equal(ddbMock.commandCalls(GetCommand).length, 1)
  })

  it('should fetch with a consistent read by transaction id', async () => {
    ddbMock.on(GetCommand).resolves({})

    const provider = createProvider()
    await provider.fetch(transactionId)

    const getCall = ddbMock.commandCalls(GetCommand)[0]
    assert.equal(getCall?.args[0].input.TableName, TABLE_NAME)
    assert.deepEqual(getCall?.args[0].input.Key, { id: transactionId })
    assert.equal(getCall?.args[0].input.ConsistentRead, true)
  })

  it('should fetch a transaction without state', async () => {
    const futureExpiry = Date.now() + 300 * 1000
    ddbMock.on(GetCommand).resolves({
      Item: { id: transactionId, ...transactionRecordWithoutState, expires_at: futureExpiry },
    })

    const provider = createProvider()
    const fetched = await provider.fetch(transactionId)

    assert.notEqual(fetched, null)
    assert.equal(fetched?.state, undefined)
    assert.equal(fetched?.nonce, transactionRecord.nonce)
  })

  it('should return null when fetching an unknown transaction', async () => {
    ddbMock.on(GetCommand).resolves({})

    const provider = createProvider()
    const fetched = await provider.fetch(TransactionId('unknown-transaction-id'))

    assert.equal(fetched, null)
  })

  it('should return null when the transaction is expired', async () => {
    const pastExpiry = Date.now() - 1000
    ddbMock.on(GetCommand).resolves({
      Item: { id: transactionId, ...transactionRecord, expires_at: pastExpiry },
    })

    const provider = createProvider()
    const fetched = await provider.fetch(transactionId)

    assert.equal(fetched, null)
  })

  it('should return null when expires_at is missing', async () => {
    ddbMock.on(GetCommand).resolves({
      Item: { id: transactionId, ...transactionRecord },
    })

    const provider = createProvider()
    const fetched = await provider.fetch(transactionId)

    assert.equal(fetched, null)
  })

  it('should reject a stored item that does not match the Transaction schema', async () => {
    const futureExpiry = Date.now() + 300 * 1000
    ddbMock.on(GetCommand).resolves({
      Item: {
        id: transactionId,
        dcqlQuery,
        clientId: transactionRecord.clientId,
        verifierId: transactionRecord.verifierId,
        expires_at: futureExpiry,
      },
    })

    const provider = createProvider()
    await assert.rejects(provider.fetch(transactionId))
  })

  it('should save with epoch-ms expires_at and epoch-seconds ttl', async () => {
    ddbMock.on(PutCommand).resolves({})
    const before = Date.now()

    const provider = createProvider()
    await provider.save(transactionId, transactionRecord)

    const after = Date.now()
    const putCall = ddbMock.commandCalls(PutCommand)[0]
    const item = putCall?.args[0].input.Item

    assert.equal(putCall?.args[0].input.TableName, TABLE_NAME)
    assert.equal(item?.id, transactionId)
    assert.equal(item?.clientId, transactionRecord.clientId)
    assert.equal(item?.verifierId, transactionRecord.verifierId)
    assert.equal(item?.state, transactionRecord.state)
    assert.equal(item?.nonce, transactionRecord.nonce)
    // expires_at is epoch ms (parity with Firestore / in-memory).
    assert.ok(item?.expires_at >= before + 300 * 1000)
    assert.ok(item?.expires_at <= after + 300 * 1000)
    // ttl is epoch seconds, rounded up so TTL never fires before the real (ms) expiry.
    assert.equal(item?.ttl, Math.ceil(item?.expires_at / 1000))
  })

  it('should store dcqlQuery as a native object, not a JSON string', async () => {
    ddbMock.on(PutCommand).resolves({})

    const provider = createProvider()
    await provider.save(transactionId, transactionRecord)

    const item = ddbMock.commandCalls(PutCommand)[0]?.args[0].input.Item
    assert.equal(typeof item?.dcqlQuery, 'object')
    assert.deepEqual(item?.dcqlQuery, transactionRecord.dcqlQuery)
  })

  it('should omit state when the record has none', async () => {
    ddbMock.on(PutCommand).resolves({})

    const provider = createProvider()
    await provider.save(transactionId, transactionRecordWithoutState)

    const item = ddbMock.commandCalls(PutCommand)[0]?.args[0].input.Item
    assert.equal(Object.hasOwn(item ?? {}, 'state'), false)
  })

  it('should use expiresIn for the expiry', async () => {
    ddbMock.on(PutCommand).resolves({})
    const before = Date.now()

    const provider = createProvider(60 * 1000)
    await provider.save(transactionId, transactionRecord)

    const after = Date.now()
    const item = ddbMock.commandCalls(PutCommand)[0]?.args[0].input.Item
    assert.ok(item?.expires_at >= before + 60 * 1000)
    assert.ok(item?.expires_at <= after + 60 * 1000)
  })

  it('should fall back to the default ttl when expiresIn is NaN', async () => {
    ddbMock.on(PutCommand).resolves({})
    const before = Date.now()

    const provider = createProvider(Number.NaN)
    await provider.save(transactionId, transactionRecord)

    const after = Date.now()
    const item = ddbMock.commandCalls(PutCommand)[0]?.args[0].input.Item
    assert.ok(Number.isFinite(item?.expires_at))
    assert.ok(Number.isFinite(item?.ttl))
    assert.ok(item?.expires_at >= before + 300 * 1000)
    assert.ok(item?.expires_at <= after + 300 * 1000)
  })

  it('should fall back to the default ttl when expiresIn is Infinity', async () => {
    ddbMock.on(PutCommand).resolves({})
    const before = Date.now()

    const provider = createProvider(Number.POSITIVE_INFINITY)
    await provider.save(transactionId, transactionRecord)

    const after = Date.now()
    const item = ddbMock.commandCalls(PutCommand)[0]?.args[0].input.Item
    assert.ok(Number.isFinite(item?.expires_at))
    assert.ok(Number.isFinite(item?.ttl))
    assert.ok(item?.expires_at >= before + 300 * 1000)
    assert.ok(item?.expires_at <= after + 300 * 1000)
  })

  it('should delete a transaction', async () => {
    ddbMock.on(DeleteCommand).resolves({})

    const provider = createProvider()
    await provider.delete(transactionId)

    const deleteCall = ddbMock.commandCalls(DeleteCommand)[0]
    assert.equal(deleteCall?.args[0].input.TableName, TABLE_NAME)
    assert.deepEqual(deleteCall?.args[0].input.Key, { id: transactionId })
  })
})
