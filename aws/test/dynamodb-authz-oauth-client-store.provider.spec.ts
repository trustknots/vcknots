import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { afterEach, describe, it } from 'node:test'
import { DynamoDBDocumentClient, GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb'
import { mockClient } from 'aws-sdk-client-mock'
import { AuthorizationServerIssuer, AuthzOAuthClient } from '@trustknots/vcknots/authz'
import { dynamodbAuthzOAuthClientStore } from '../src/providers/dynamodb-authz-oauth-client-store.provider'

const TABLE_NAME = 'AuthzOAuthClientsTable'
const ddbMock = mockClient(DynamoDBDocumentClient)

describe('dynamodbAuthzOAuthClientStore', () => {
  const md5 = (value: string) => createHash('md5').update(value).digest('base64url')
  const id = (issuer: AuthorizationServerIssuer, clientId: string) => `${md5(issuer)}#${clientId}`

  const issuer = AuthorizationServerIssuer('https://authz.example.com')
  const client = AuthzOAuthClient({
    client_id: 'client-1',
    client_name: 'Client 1',
    token_endpoint_auth_method: 'private_key_jwt',
    senderConstrainedAccessToken: {
      method: 'dpop',
      dpop: { mode: 'required' },
    },
    enabled: true,
  })

  afterEach(() => {
    ddbMock.reset()
  })

  const createProvider = () =>
    dynamodbAuthzOAuthClientStore({
      client: ddbMock as unknown as DynamoDBDocumentClient,
      tableName: TABLE_NAME,
    })

  it('should have correct provider metadata', () => {
    const provider = createProvider()
    assert.equal(provider.kind, 'authz-oauth-client-store-provider')
    assert.equal(provider.name, 'dynamodb-authz-oauth-client-store-provider')
    assert.equal(provider.single, true)
  })

  it('should save and fetch an OAuth client', async () => {
    const expectedId = id(issuer, client.client_id)
    ddbMock.on(PutCommand).resolves({})
    ddbMock.on(GetCommand).resolves({
      Item: { id: expectedId, issuer, ...client },
    })

    const provider = createProvider()
    await provider.save(issuer, client)
    const fetched = await provider.fetch(issuer, client.client_id)

    assert.deepEqual(fetched, client)
  })

  it('should use the composite id (hashed issuer + clientId) as the partition key', async () => {
    ddbMock.on(PutCommand).resolves({})
    const expectedId = id(issuer, client.client_id)

    const provider = createProvider()
    await provider.save(issuer, client)

    const putCall = ddbMock.commandCalls(PutCommand)[0]
    assert.equal(putCall?.args[0].input.TableName, TABLE_NAME)
    assert.equal(putCall?.args[0].input.Item?.id, expectedId)
    assert.equal(putCall?.args[0].input.Item?.issuer, issuer)
  })

  it('should store distinct records for different clients under the same issuer', async () => {
    ddbMock.on(PutCommand).resolves({})
    const other = AuthzOAuthClient({ client_id: 'client-2' })

    const provider = createProvider()
    await provider.save(issuer, client)
    await provider.save(issuer, other)

    const [first, second] = ddbMock.commandCalls(PutCommand)
    assert.notEqual(first.args[0].input.Item?.id, second.args[0].input.Item?.id)
  })

  it('should return null when fetching an unknown client', async () => {
    ddbMock.on(GetCommand).resolves({})

    const provider = createProvider()
    const fetched = await provider.fetch(issuer, 'unknown-client')

    assert.equal(fetched, null)
  })

  it('should return null for a disabled client', async () => {
    const disabled = AuthzOAuthClient({ client_id: 'disabled-client', enabled: false })
    ddbMock.on(GetCommand).resolves({
      Item: { id: id(issuer, disabled.client_id), issuer, ...disabled },
    })

    const provider = createProvider()
    const fetched = await provider.fetch(issuer, disabled.client_id)

    assert.equal(fetched, null)
  })

  it('should fully replace an existing client on save', async () => {
    const expectedId = id(issuer, client.client_id)
    const updated: AuthzOAuthClient = { ...client, client_name: 'Updated Client' }

    ddbMock.on(PutCommand).resolves({})
    ddbMock.on(GetCommand).resolves({
      Item: { id: expectedId, issuer, ...updated },
    })

    const provider = createProvider()
    await provider.save(issuer, client)
    await provider.save(issuer, updated)

    const fetched = await provider.fetch(issuer, client.client_id)
    assert.deepEqual(fetched, updated)
    assert.equal(ddbMock.commandCalls(PutCommand).length, 2)
  })
})
