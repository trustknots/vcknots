import assert from 'node:assert'
import { beforeEach, describe, it, test } from 'node:test'
import { inMemoryVerifierTransactionDataStore } from '../../../src/providers/in-memory/in-memory-verifier-transaction-store'
import { TransactionId, TransactionRecord } from '../../../src/transaction-id.types'

describe('inMemoryVerifierTransactionDataStore', () => {
  let transactionStoreProvider: ReturnType<typeof inMemoryVerifierTransactionDataStore>
  const testTransactionId = TransactionId('test-transaction-id')
  const testTransactionRecord = TransactionRecord({
    dcqlQuery: {
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
    },
    clientId: 'redirect_uri:https://example.com',
  })

  describe('When initialized with no options (default behavior)', () => {
    beforeEach(() => {
      transactionStoreProvider = inMemoryVerifierTransactionDataStore()
    })

    it('should have correct kind, name, and single properties', () => {
      assert.strictEqual(transactionStoreProvider.kind, 'verifier-transaction-data-store-provider')
      assert.strictEqual(transactionStoreProvider.name, 'in-memory-transaction-data-provider')
      assert.strictEqual(transactionStoreProvider.single, true)
    })

    it('save should store the transaction record, making it fetchable immediately', async () => {
      await transactionStoreProvider.save(testTransactionId, testTransactionRecord)
      const transaction = await transactionStoreProvider.fetch(testTransactionId)

      assert.notStrictEqual(transaction, null)
      assert.strictEqual(transaction?.transaction_id, testTransactionId)
      assert.deepStrictEqual(transaction?.dcqlQuery, testTransactionRecord.dcqlQuery)
    })

    it('fetch should return null for a non-existent transaction id', async () => {
      const transaction = await transactionStoreProvider.fetch(TransactionId('non-existent-id'))
      assert.strictEqual(transaction, null)
    })

    it('delete should remove the transaction, making it unavailable', async () => {
      await transactionStoreProvider.save(testTransactionId, testTransactionRecord)
      await transactionStoreProvider.delete(testTransactionId)

      const transaction = await transactionStoreProvider.fetch(testTransactionId)
      assert.strictEqual(transaction, null)
    })

    it('delete should not throw for a non-existent transaction id', async () => {
      await assert.doesNotReject(async () => {
        await transactionStoreProvider.delete(TransactionId('non-existent-id'))
      })
    })

    it('fetch should return the transaction before its default expiration time (using mocked time)', async () => {
      const oneMinuteInMs = 1 * 60 * 1000
      const mocks = test.mock.timers
      mocks.enable()
      await transactionStoreProvider.save(testTransactionId, testTransactionRecord)
      try {
        mocks.tick(oneMinuteInMs)
        const transaction = await transactionStoreProvider.fetch(testTransactionId)
        assert.notStrictEqual(transaction, null)
      } finally {
        mocks.reset()
      }
    })

    it('fetch should return null for an expired transaction after default expiration (using mocked time)', async () => {
      const fiveMinutesInMs = 5 * 60 * 1000
      const mocks = test.mock.timers
      mocks.enable()
      await transactionStoreProvider.save(testTransactionId, testTransactionRecord)
      try {
        mocks.tick(fiveMinutesInMs + 1000)
        const transaction = await transactionStoreProvider.fetch(testTransactionId)
        assert.strictEqual(transaction, null)
      } finally {
        mocks.reset()
      }
    })
  })

  describe('When initialized with custom expiration option', () => {
    const testExpiryMs = 3 * 60 * 1000

    beforeEach(() => {
      transactionStoreProvider = inMemoryVerifierTransactionDataStore({
        transaction_data_expire_in: testExpiryMs,
      })
    })

    it('save should store the transaction with custom expiration, fetchable immediately', async () => {
      await transactionStoreProvider.save(testTransactionId, testTransactionRecord)
      const transaction = await transactionStoreProvider.fetch(testTransactionId)

      assert.notStrictEqual(transaction, null)
      assert.strictEqual(transaction?.transaction_id, testTransactionId)
      assert.deepStrictEqual(transaction?.dcqlQuery, testTransactionRecord.dcqlQuery)
    })

    it('fetch should return the transaction before its custom expiration time (using mocked time)', async () => {
      const oneMinuteInMs = 1 * 60 * 1000
      const mocks = test.mock.timers
      mocks.enable()
      await transactionStoreProvider.save(testTransactionId, testTransactionRecord)
      try {
        mocks.tick(oneMinuteInMs)
        const transaction = await transactionStoreProvider.fetch(testTransactionId)
        assert.notStrictEqual(transaction, null)
      } finally {
        mocks.reset()
      }
    })

    it('fetch should return null for an expired transaction after custom expiration (using mocked time)', async () => {
      const fiveMinutesInMs = 5 * 60 * 1000
      const mocks = test.mock.timers
      mocks.enable()
      await transactionStoreProvider.save(testTransactionId, testTransactionRecord)
      try {
        mocks.tick(fiveMinutesInMs)
        const transaction = await transactionStoreProvider.fetch(testTransactionId)
        assert.strictEqual(transaction, null)
      } finally {
        mocks.reset()
      }
    })
  })

  describe('Method return types', () => {
    beforeEach(() => {
      transactionStoreProvider = inMemoryVerifierTransactionDataStore()
    })

    it('save method should return a Promise that resolves to undefined', async () => {
      const result = await transactionStoreProvider.save(testTransactionId, testTransactionRecord)
      assert.strictEqual(result, undefined)
    })

    it('delete method should return a Promise that resolves to undefined', async () => {
      await transactionStoreProvider.save(testTransactionId, testTransactionRecord)
      const result = await transactionStoreProvider.delete(testTransactionId)
      assert.strictEqual(result, undefined)
    })
  })
})
