import 'dotenv/config'
import { dynamodbIssuerMetadataStore } from '@trustknots/aws'
import { createServer } from '@trustknots/server-core'

const tableName = process.env.ISSUERS_TABLE_NAME
if (!tableName) {
  throw new Error('ISSUERS_TABLE_NAME is required')
}

process.env.BASE_URL ??= 'http://localhost:8081'
process.env.PORT ??= '8081'

createServer({
  providers: [dynamodbIssuerMetadataStore({ tableName })],
})
