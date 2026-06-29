import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { afterEach, describe, it } from 'node:test'
import { DynamoDBDocumentClient, GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb'
import { mockClient } from 'aws-sdk-client-mock'
import { VerifierClientId, VerifierMetadata } from '@trustknots/vcknots/verifier'
import { dynamodbVerifierMetadataStore } from '../src/providers/dynamodb-verifier-metadata-store.provider'

const TABLE_NAME = 'VerifiersTable'
const ddbMock = mockClient(DynamoDBDocumentClient)

describe('dynamodbVerifierMetadataStore', () => {
  const md5 = (value: string) => createHash('md5').update(value).digest('base64url')

  const verifierId = VerifierClientId('https://verifier.example.com')
  const metadata: VerifierMetadata = {
    vp_formats: {
      jwt_vc_json: { alg_values_supported: ['ES256'] },
      jwt_vp_json: { alg_values_supported: ['ES256'] },
    },
  }

  afterEach(() => {
    ddbMock.reset()
  })

  const createProvider = () =>
    dynamodbVerifierMetadataStore({
      client: ddbMock as unknown as DynamoDBDocumentClient,
      tableName: TABLE_NAME,
    })

  it('should have correct provider metadata', () => {
    const provider = createProvider()
    assert.equal(provider.kind, 'verifier-metadata-store-provider')
    assert.equal(provider.name, 'dynamodb-verifier-metadata-store-provider')
    assert.equal(provider.single, true)
  })

  it('should save and fetch verifier metadata', async () => {
    const expectedId = md5(verifierId)
    ddbMock.on(PutCommand).resolves({})
    ddbMock.on(GetCommand).resolves({
      Item: { id: expectedId, ...metadata },
    })

    const provider = createProvider()
    await provider.save(verifierId, metadata)
    const fetched = await provider.fetch(verifierId)

    assert.deepEqual(fetched, metadata)
    assert.equal(ddbMock.commandCalls(PutCommand).length, 1)
    assert.equal(ddbMock.commandCalls(GetCommand).length, 1)
  })

  it('should return null when fetching metadata for an unknown verifier', async () => {
    ddbMock.on(GetCommand).resolves({})

    const provider = createProvider()
    const fetched = await provider.fetch(VerifierClientId('https://unknown.example.com'))

    assert.equal(fetched, null)
  })

  it('should use the correct partition key id', async () => {
    ddbMock.on(PutCommand).resolves({})
    const expectedId = md5(verifierId)

    const provider = createProvider()
    await provider.save(verifierId, metadata)

    const putCall = ddbMock.commandCalls(PutCommand)[0]
    assert.equal(putCall?.args[0].input.TableName, TABLE_NAME)
    assert.equal(putCall?.args[0].input.Item?.id, expectedId)
  })

  it('should fully replace existing metadata on save', async () => {
    const expectedId = md5(verifierId)
    const updated: VerifierMetadata = {
      ...metadata,
      client_name: 'Updated Verifier',
      vp_formats: {
        'dc+sd-jwt': { 'sd-jwt_alg_values': ['ES256'], 'kb-jwt_alg_values': ['ES256'] },
      },
    }

    ddbMock.on(PutCommand).resolves({})
    ddbMock.on(GetCommand).resolves({
      Item: { id: expectedId, ...updated },
    })

    const provider = createProvider()
    await provider.save(verifierId, metadata)
    await provider.save(verifierId, updated)

    const fetched = await provider.fetch(verifierId)
    assert.notEqual(fetched, null)
    assert.deepEqual(fetched, updated)
    assert.equal(ddbMock.commandCalls(PutCommand).length, 2)
  })
})
