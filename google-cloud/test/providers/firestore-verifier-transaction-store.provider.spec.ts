import assert from 'node:assert/strict'
import { afterEach, describe, it } from 'node:test'
import { TransactionId, TransactionRecord } from '@trustknots/vcknots'
import { firestoreVerifierTransactionDataStore } from '../../src/providers/firestore-verifier-transaction-store.provider'
import { createFirestoreTestMock } from './firestore-test-mock'

const { store, mockApp } = createFirestoreTestMock()

describe('firestoreVerifierTransactionDataStore', () => {
  const transactionId = TransactionId('test-transaction-id')
  const transactionRecord = TransactionRecord({
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

  afterEach(() => {
    store.clear()
  })

  it('should have correct provider metadata', () => {
    const provider = firestoreVerifierTransactionDataStore({ app: mockApp })
    assert.equal(provider.kind, 'verifier-transaction-data-store-provider')
    assert.equal(provider.name, 'firestore-verifier-transaction-data-store-provider')
    assert.equal(provider.single, true)
  })

  it('should save and fetch a transaction', async () => {
    const provider = firestoreVerifierTransactionDataStore({ app: mockApp })
    await provider.save(transactionId, transactionRecord)

    const transaction = await provider.fetch(transactionId)
    assert.notEqual(transaction, null)
    assert.equal(transaction?.transaction_id, transactionId)
    assert.deepEqual(transaction?.dcqlQuery, transactionRecord.dcqlQuery)
  })

  it('should return null when fetching an unknown transaction', async () => {
    const provider = firestoreVerifierTransactionDataStore({ app: mockApp })
    const transaction = await provider.fetch(TransactionId('unknown-transaction-id'))
    assert.equal(transaction, null)
  })

  it('should return null and delete when fetching an expired transaction', async () => {
    const provider = firestoreVerifierTransactionDataStore({
      app: mockApp,
      transaction_data_expire_in: -1,
    })
    await provider.save(transactionId, transactionRecord)

    const transaction = await provider.fetch(transactionId)
    assert.equal(transaction, null)
    assert.ok(!store.has(`vcknots/v1/verifierTransactions/${transactionId}`))
  })

  it('should delete a transaction', async () => {
    const provider = firestoreVerifierTransactionDataStore({ app: mockApp })
    await provider.save(transactionId, transactionRecord)
    await provider.delete(transactionId)
    assert.ok(!store.has(`vcknots/v1/verifierTransactions/${transactionId}`))
  })

  it('should reject invalid transaction ids before save', async () => {
    const provider = firestoreVerifierTransactionDataStore({ app: mockApp })
    await assert.rejects(
      provider.save('invalid/id' as TransactionId, transactionRecord),
      /Invalid transaction ID/
    )
  })

  it('should reject invalid transaction ids before fetch', async () => {
    const provider = firestoreVerifierTransactionDataStore({ app: mockApp })
    await assert.rejects(provider.fetch('invalid/id' as TransactionId), /Invalid transaction ID/)
  })

  it('should reject invalid transaction ids before delete', async () => {
    const provider = firestoreVerifierTransactionDataStore({ app: mockApp })
    await assert.rejects(provider.delete('invalid/id' as TransactionId), /Invalid transaction ID/)
  })

  it('should use the correct Firestore document path', async () => {
    const provider = firestoreVerifierTransactionDataStore({ app: mockApp })
    await provider.save(transactionId, transactionRecord)
    assert.ok(store.has(`vcknots/v1/verifierTransactions/${transactionId}`))
  })

  it('should use a custom namespace', async () => {
    const provider = firestoreVerifierTransactionDataStore({ app: mockApp, namespace: 'custom' })
    await provider.save(transactionId, transactionRecord)
    assert.ok(store.has(`custom/v1/verifierTransactions/${transactionId}`))
    assert.ok(!store.has(`vcknots/v1/verifierTransactions/${transactionId}`))
  })

  it('should strip all slashes from namespace', async () => {
    const provider = firestoreVerifierTransactionDataStore({
      app: mockApp,
      namespace: 'foo/bar/baz',
    })
    await provider.save(transactionId, transactionRecord)
    assert.ok(store.has(`foobarbaz/v1/verifierTransactions/${transactionId}`))
    assert.ok(!store.has(`foo/bar/baz/v1/verifierTransactions/${transactionId}`))
  })

  it('should strip leading and trailing slashes from namespace', async () => {
    const provider = firestoreVerifierTransactionDataStore({
      app: mockApp,
      namespace: '/my/ns/',
    })
    await provider.save(transactionId, transactionRecord)
    assert.ok(store.has(`myns/v1/verifierTransactions/${transactionId}`))
  })

  it('should fall back to vcknots when namespace is only slashes', async () => {
    const provider = firestoreVerifierTransactionDataStore({ app: mockApp, namespace: '///' })
    await provider.save(transactionId, transactionRecord)
    assert.ok(store.has(`vcknots/v1/verifierTransactions/${transactionId}`))
  })
})
