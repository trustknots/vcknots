import { createHash } from 'node:crypto'
import { GetCommand, PutCommand } from '@aws-sdk/lib-dynamodb'
import { VerifierClientId, VerifierMetadata } from '@trustknots/vcknots/verifier'
import { VerifierMetadataStoreProvider } from '@trustknots/vcknots/providers'
import { DynamoDbProviderOptions, resolveDynamoDbDocumentClient } from './dynamodb'

export type DynamoDbVerifierMetadataStoreOptions = DynamoDbProviderOptions & {
  tableName: string
}

const md5 = (verifier: VerifierClientId): string =>
  createHash('md5').update(verifier).digest('base64url')

export const dynamodbVerifierMetadataStore = (
  options: DynamoDbVerifierMetadataStoreOptions
): VerifierMetadataStoreProvider => {
  const client = resolveDynamoDbDocumentClient(options)
  const { tableName } = options

  return {
    kind: 'verifier-metadata-store-provider',
    name: 'dynamodb-verifier-metadata-store-provider',
    single: true,

    async fetch(verifier) {
      const id = md5(verifier)
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
      return VerifierMetadata(data)
    },

    async save(verifier, metadata) {
      const id = md5(verifier)
      await client.send(
        new PutCommand({
          TableName: tableName,
          Item: { id, ...metadata },
        })
      )
    },
  }
}
