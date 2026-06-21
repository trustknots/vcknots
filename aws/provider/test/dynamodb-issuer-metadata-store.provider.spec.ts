import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { afterEach, describe, it } from 'node:test'
import { DynamoDBDocumentClient, GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb'
import { mockClient } from 'aws-sdk-client-mock'
import { CredentialIssuer, CredentialIssuerMetadata } from '@trustknots/vcknots/issuer'
import { dynamodbIssuerMetadataStore } from '../src/dynamodb-issuer-metadata-store.provider'

const TABLE_NAME = 'IssuersTable'
const ddbMock = mockClient(DynamoDBDocumentClient)

describe('dynamodbIssuerMetadataStore', () => {
  const md5 = (value: string) => createHash('md5').update(value).digest('base64url')

  const metadata: CredentialIssuerMetadata = {
    credential_issuer: CredentialIssuer('https://example.com/issuer'),
    credential_endpoint: 'https://example.com/issuer/credential',
    authorization_servers: ['https://example.com/authz'],
    credential_configurations_supported: {
      EmployeeID_jwt_vc_json: {
        format: 'jwt_vc_json',
        scope: 'employee_id',
        cryptographic_binding_methods_supported: ['did:example'],
        credential_definition: {
          type: ['VerifiableCredential', 'EmployeeIDCredential'],
        },
        proof_types_supported: {
          jwt: {
            proof_signing_alg_values_supported: ['ES256'],
          },
        },
        credential_signing_alg_values_supported: ['ES256'],
      },
    },
  }

  afterEach(() => {
    ddbMock.reset()
  })

  const createProvider = () =>
    dynamodbIssuerMetadataStore({
      client: ddbMock as unknown as DynamoDBDocumentClient,
      tableName: TABLE_NAME,
    })

  it('should have correct provider metadata', () => {
    const provider = createProvider()
    assert.equal(provider.kind, 'issuer-metadata-store-provider')
    assert.equal(provider.name, 'dynamodb-issuer-metadata-store-provider')
    assert.equal(provider.single, true)
  })

  it('should save and fetch issuer metadata', async () => {
    const expectedId = md5(metadata.credential_issuer)
    ddbMock.on(PutCommand).resolves({})
    ddbMock.on(GetCommand).resolves({
      Item: { id: expectedId, ...metadata },
    })

    const provider = createProvider()
    await provider.save(metadata)
    const fetched = await provider.fetch(metadata.credential_issuer)

    assert.deepEqual(fetched, metadata)
    assert.equal(ddbMock.commandCalls(PutCommand).length, 1)
    assert.equal(ddbMock.commandCalls(GetCommand).length, 1)
  })

  it('should return null when fetching metadata for an unknown issuer', async () => {
    ddbMock.on(GetCommand).resolves({})

    const provider = createProvider()
    const fetched = await provider.fetch(CredentialIssuer('https://unknown.example.com/issuer'))

    assert.equal(fetched, null)
  })

  it('should use the correct partition key id', async () => {
    ddbMock.on(PutCommand).resolves({})
    const expectedId = md5(metadata.credential_issuer)

    const provider = createProvider()
    await provider.save(metadata)

    const putCall = ddbMock.commandCalls(PutCommand)[0]
    assert.equal(putCall?.args[0].input.TableName, TABLE_NAME)
    assert.equal(putCall?.args[0].input.Item?.id, expectedId)
  })

  it('should fully replace existing metadata on save', async () => {
    const expectedId = md5(metadata.credential_issuer)
    const updated: CredentialIssuerMetadata = {
      ...metadata,
      credential_endpoint: 'https://example.com/issuer/updated_credential',
      authorization_servers: ['https://example.com/new-authz'],
    }

    ddbMock.on(PutCommand).resolves({})
    ddbMock.on(GetCommand).resolves({
      Item: { id: expectedId, ...updated },
    })

    const provider = createProvider()
    await provider.save(metadata)
    await provider.save(updated)

    const fetched = await provider.fetch(metadata.credential_issuer)
    assert.notEqual(fetched, null)
    assert.deepEqual(fetched, updated)
    assert.equal(ddbMock.commandCalls(PutCommand).length, 2)
  })
})
