import { DynamoDBClient } from '@aws-sdk/client-dynamodb'
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb'

export type DynamoDbProviderOptions = {
  client?: DynamoDBDocumentClient
}

export const resolveDynamoDbDocumentClient = (
  options?: DynamoDbProviderOptions
): DynamoDBDocumentClient => {
  if (options?.client) {
    return options.client
  }

  const dynamoDbClient = new DynamoDBClient({})
  return DynamoDBDocumentClient.from(dynamoDbClient)
}
