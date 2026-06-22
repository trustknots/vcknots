import { createHash } from 'node:crypto'
import { GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb'
import { CredentialIssuer, CredentialIssuerMetadata } from '@trustknots/vcknots/issuer'
import { IssuerMetadataStoreProvider } from '@trustknots/vcknots/providers'
import { DynamoDbProviderOptions, resolveDynamoDbDocumentClient } from './dynamodb.provider'

export type DynamoDbIssuerMetadataStoreOptions = DynamoDbProviderOptions & {
  tableName: string
}

const md5 = (issuer: CredentialIssuer): string =>
  createHash('md5').update(issuer).digest('base64url')

export const dynamodbIssuerMetadataStore = (
  options: DynamoDbIssuerMetadataStoreOptions
): IssuerMetadataStoreProvider => {
  const client = resolveDynamoDbDocumentClient(options)
  const { tableName } = options

  return {
    kind: 'issuer-metadata-store-provider',
    name: 'dynamodb-issuer-metadata-store-provider',
    single: true,

    async fetch(issuer) {
      const id = md5(issuer)
      const result = await client.send(
        new GetCommand({
          TableName: tableName,
          Key: { id },
        })
      )

      if (!result.Item) {
        return null
      }

      const { id: _id, ...data } = result.Item
      return CredentialIssuerMetadata(data)
    },

    async save(issuer) {
      const id = md5(issuer.credential_issuer)
      await client.send(
        new PutCommand({
          TableName: tableName,
          Item: { id, ...issuer },
        })
      )
    },
  }
}
