import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { dynamodbRequestObjectStore, dynamodbVerifierMetadataStore } from '@trustknots/aws'
import { createVerifierRouter } from '@trustknots/server-core/routes/verify'
import { VerifierClientId, VerifierMetadata, initializeVerifierFlow } from '@trustknots/vcknots/verifier'
import type { VcknotsOptions } from '@trustknots/vcknots'
import { createBaseApp } from './create-base-app.js'
import { createVcknotsContext } from '../context/vcknots-context.js'

export function createVerifierApp(options?: VcknotsOptions) {
  const verifiersTableName = process.env.VERIFIERS_TABLE_NAME
  if (!verifiersTableName) {
    throw new Error('VERIFIERS_TABLE_NAME is required')
  }

  const requestObjectsTableName = process.env.REQUEST_OBJECTS_TABLE_NAME
  if (!requestObjectsTableName) {
    throw new Error('REQUEST_OBJECTS_TABLE_NAME is required')
  }

  const rawPort = process.env.VERIFIER_PORT ?? '8083'
  const port = Number.parseInt(rawPort, 10)
  if (!Number.isFinite(port)) throw new Error(`Invalid VERIFIER_PORT: "${rawPort}"`)

  const verifierMetadataStore = dynamodbVerifierMetadataStore({ tableName: verifiersTableName })
  const requestObjectStore = dynamodbRequestObjectStore({ tableName: requestObjectsTableName })
  const { app } = createBaseApp(
    createVerifierRouter,
    { port, baseUrl: process.env.VERIFIER_BASE_URL },
    { ...options, providers: [verifierMetadataStore, requestObjectStore, ...(options?.providers ?? [])] },
  )

  async function initialize(baseUrl: string) {
    const verifierId = VerifierClientId(baseUrl)
    const context = createVcknotsContext({ ...options, providers: [verifierMetadataStore, requestObjectStore, ...(options?.providers ?? [])] })
    const verifierFlow = initializeVerifierFlow(context)

    const existing = await verifierFlow.findVerifierMetadata(verifierId)
    if (existing) {
      console.log('Verifier metadata already exists, skipping initialization')
      return
    }

    const samplesDir = join(dirname(fileURLToPath(import.meta.url)), '../../../samples')
    const sampleVerifierMetadata = JSON.parse(readFileSync(join(samplesDir, 'verifier_metadata.json'), 'utf-8'))

    const metadata = VerifierMetadata(sampleVerifierMetadata)
    await verifierFlow.createVerifierMetadata(verifierId, metadata)
    console.log('Verifier metadata initialized')
  }

  return { app, initialize }
}
