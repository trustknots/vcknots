import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { afterEach, describe, it } from 'node:test'
import { DynamoDBDocumentClient, GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb'
import { mockClient } from 'aws-sdk-client-mock'
import { AuthorizationServerIssuer, AuthzOAuthPolicy } from '@trustknots/vcknots/authz'
import { dynamodbAuthzOAuthPolicyStore } from '../src/providers/dynamodb-authz-oauth-policy-store.provider'

const TABLE_NAME = 'AuthzOAuthPoliciesTable'
const ddbMock = mockClient(DynamoDBDocumentClient)

describe('dynamodbAuthzOAuthPolicyStore', () => {
  const md5 = (value: string) => createHash('md5').update(value).digest('base64url')

  const issuer = AuthorizationServerIssuer('https://authz.example.com')
  const policy = AuthzOAuthPolicy({
    default_client: {
      senderConstrainedAccessToken: {
        method: 'dpop',
        dpop: { mode: 'optional' },
      },
    },
    anonymous_client: {
      senderConstrainedAccessToken: {
        method: 'dpop',
        dpop: { mode: 'required' },
      },
    },
  })

  afterEach(() => {
    ddbMock.reset()
  })

  const createProvider = () =>
    dynamodbAuthzOAuthPolicyStore({
      client: ddbMock as unknown as DynamoDBDocumentClient,
      tableName: TABLE_NAME,
    })

  it('should have correct provider metadata', () => {
    const provider = createProvider()
    assert.equal(provider.kind, 'authz-oauth-policy-store-provider')
    assert.equal(provider.name, 'dynamodb-authz-oauth-policy-store-provider')
    assert.equal(provider.single, true)
  })

  it('should save and fetch an authz OAuth policy', async () => {
    const expectedId = md5(issuer)
    ddbMock.on(PutCommand).resolves({})
    ddbMock.on(GetCommand).resolves({
      Item: { id: expectedId, issuer, ...policy },
    })

    const provider = createProvider()
    await provider.save(issuer, policy)
    const fetched = await provider.fetch(issuer)

    assert.deepEqual(fetched, policy)
  })

  it('should use the hashed issuer as the partition key', async () => {
    ddbMock.on(PutCommand).resolves({})
    const expectedId = md5(issuer)

    const provider = createProvider()
    await provider.save(issuer, policy)

    const putCall = ddbMock.commandCalls(PutCommand)[0]
    assert.equal(putCall?.args[0].input.TableName, TABLE_NAME)
    assert.equal(putCall?.args[0].input.Item?.id, expectedId)
    assert.equal(putCall?.args[0].input.Item?.issuer, issuer)
  })

  it('should return null when fetching policy for an unknown issuer', async () => {
    ddbMock.on(GetCommand).resolves({})

    const provider = createProvider()
    const fetched = await provider.fetch(AuthorizationServerIssuer('https://unknown.example.com'))

    assert.equal(fetched, null)
  })

  it('should fully replace an existing policy on save', async () => {
    const expectedId = md5(issuer)
    const updated = AuthzOAuthPolicy({
      default_client: {
        senderConstrainedAccessToken: { method: 'none' },
      },
    })

    ddbMock.on(PutCommand).resolves({})
    ddbMock.on(GetCommand).resolves({
      Item: { id: expectedId, issuer, ...updated },
    })

    const provider = createProvider()
    await provider.save(issuer, policy)
    await provider.save(issuer, updated)

    const fetched = await provider.fetch(issuer)
    assert.deepEqual(fetched, updated)
    assert.equal(ddbMock.commandCalls(PutCommand).length, 2)
  })
})
