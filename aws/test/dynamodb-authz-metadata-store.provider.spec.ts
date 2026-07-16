import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { afterEach, describe, it } from 'node:test'
import { DynamoDBDocumentClient, GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb'
import { mockClient } from 'aws-sdk-client-mock'
import { AuthorizationServerIssuer, AuthorizationServerMetadata } from '@trustknots/vcknots/authz'
import { dynamodbAuthzServerMetadataStore } from '../src/providers/dynamodb-authz-metadata-store.provider'

const TABLE_NAME = 'AuthServersTable'
const ddbMock = mockClient(DynamoDBDocumentClient)

describe('dynamodbAuthzServerMetadataStore', () => {
  const md5 = (value: string) => createHash('md5').update(value).digest('base64url')

  const metadata: AuthorizationServerMetadata = {
    issuer: AuthorizationServerIssuer('https://authz.example.com'),
    authorization_endpoint: 'https://authz.example.com/authorize',
    token_endpoint: 'https://authz.example.com/token',
    response_types_supported: ['code'],
  }

  afterEach(() => {
    ddbMock.reset()
  })

  const createProvider = () =>
    dynamodbAuthzServerMetadataStore({
      client: ddbMock as unknown as DynamoDBDocumentClient,
      tableName: TABLE_NAME,
    })

  it('should have correct provider metadata', () => {
    const provider = createProvider()
    assert.equal(provider.kind, 'authz-server-metadata-store-provider')
    assert.equal(provider.name, 'dynamodb-authz-server-metadata-store-provider')
    assert.equal(provider.single, true)
  })

  it('should save and fetch authz server metadata', async () => {
    const expectedId = md5(metadata.issuer)
    ddbMock.on(PutCommand).resolves({})
    ddbMock.on(GetCommand).resolves({
      Item: { id: expectedId, ...metadata },
    })

    const provider = createProvider()
    await provider.save(metadata)
    const fetched = await provider.fetch(metadata.issuer)

    assert.deepEqual(fetched, metadata)
    assert.equal(ddbMock.commandCalls(PutCommand).length, 1)
    assert.equal(ddbMock.commandCalls(GetCommand).length, 1)
  })

  it('should return null when fetching metadata for an unknown issuer', async () => {
    ddbMock.on(GetCommand).resolves({})

    const provider = createProvider()
    const fetched = await provider.fetch(AuthorizationServerIssuer('https://unknown.example.com'))

    assert.equal(fetched, null)
  })

  it('should use the correct partition key id', async () => {
    ddbMock.on(PutCommand).resolves({})
    const expectedId = md5(metadata.issuer)

    const provider = createProvider()
    await provider.save(metadata)

    const putCall = ddbMock.commandCalls(PutCommand)[0]
    assert.equal(putCall?.args[0].input.TableName, TABLE_NAME)
    assert.equal(putCall?.args[0].input.Item?.id, expectedId)
  })

  it('should fully replace existing metadata on save', async () => {
    const expectedId = md5(metadata.issuer)
    const updated: AuthorizationServerMetadata = {
      ...metadata,
      token_endpoint: 'https://authz.example.com/updated_token',
      scopes_supported: ['openid'],
    }

    ddbMock.on(PutCommand).resolves({})
    ddbMock.on(GetCommand).resolves({
      Item: { id: expectedId, ...updated },
    })

    const provider = createProvider()
    await provider.save(metadata)
    await provider.save(updated)

    const fetched = await provider.fetch(metadata.issuer)
    assert.notEqual(fetched, null)
    assert.deepEqual(fetched, updated)
    assert.equal(ddbMock.commandCalls(PutCommand).length, 2)
  })
})
