import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  dynamodbNonceStore,
  dynamodbRequestObjectStore,
  dynamodbVerifierMetadataStore,
  kmsVerifierSignatureKeyStore,
} from '@trustknots/aws'
import { createVerifierRouter } from '@trustknots/server-core/routes/verify'
import { VerifierClientId, VerifierMetadata, initializeVerifierFlow } from '@trustknots/vcknots/verifier'
import type { VcknotsOptions } from '@trustknots/vcknots'
import { createBaseApp } from './create-base-app.js'

export function createVerifierApp(options?: VcknotsOptions) {
  const verifiersTableName = process.env.VERIFIERS_TABLE_NAME
  if (!verifiersTableName) {
    throw new Error('VERIFIERS_TABLE_NAME is required')
  }

  const requestObjectsTableName = process.env.REQUEST_OBJECTS_TABLE_NAME
  if (!requestObjectsTableName) {
    throw new Error('REQUEST_OBJECTS_TABLE_NAME is required')
  }

  const noncesTableName = process.env.NONCES_TABLE_NAME
  if (!noncesTableName) {
    throw new Error('NONCES_TABLE_NAME is required')
  }

  const rawPort = process.env.VERIFIER_PORT ?? '8083'
  const port = Number.parseInt(rawPort, 10)
  if (!Number.isFinite(port)) throw new Error(`Invalid VERIFIER_PORT: "${rawPort}"`)

  const verifierMetadataStore = dynamodbVerifierMetadataStore({ tableName: verifiersTableName })
  const requestObjectStore = dynamodbRequestObjectStore({ tableName: requestObjectsTableName })
  const nonceStore = dynamodbNonceStore({ tableName: noncesTableName })
  const signatureKeyStore = kmsVerifierSignatureKeyStore()
  const { app, context } = createBaseApp(
    createVerifierRouter,
    { port, baseUrl: process.env.VERIFIER_BASE_URL },
    {
      ...options,
      providers: [
        verifierMetadataStore,
        requestObjectStore,
        nonceStore,
        signatureKeyStore,
        ...(options?.providers ?? []),
      ],
    },
  )

  async function initialize(baseUrl: string) {
    const verifierId = VerifierClientId(baseUrl)
    const verifierFlow = initializeVerifierFlow(context)

    const existing = await verifierFlow.findVerifierMetadata(verifierId)
    if (existing) {
      console.log('Verifier metadata already exists, skipping initialization')
      // Metadata (DynamoDB) and the signing key (KMS) live in separate stores, so they can drift
      // apart — most often when an environment that ran on the in-memory key store is pointed at
      // KMS. createVerifierMetadata rejects an already-registered verifier and cannot repair that,
      // so just make the gap visible.
      const keyAlg = existing.authorization_signed_response_alg ?? 'ES256'
      const publicKey = await signatureKeyStore.fetch(verifierId, keyAlg)
      if (!publicKey) {
        console.warn(
          `Verifier metadata exists but no ${keyAlg} key is registered in KMS: signing authorization requests will fail`,
        )
      }
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
