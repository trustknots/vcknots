import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  dynamodbAuthzOAuthClientStore,
  dynamodbAuthzServerMetadataStore,
  dynamodbPreAuthorizedCodeStore,
  kmsAuthzSignatureKeyStore,
} from '@trustknots/aws'
import { createAuthzRouter } from '@trustknots/server-core/routes/authz'
import {
  AuthorizationServerIssuer,
  AuthorizationServerMetadata,
  initializeAuthzFlow,
} from '@trustknots/vcknots/authz'
import type { VcknotsOptions } from '@trustknots/vcknots'
import { createBaseApp } from './create-base-app.js'

export function createAuthzApp(options?: VcknotsOptions) {
  const authServersTableName = process.env.AUTH_SERVERS_TABLE_NAME
  if (!authServersTableName) {
    throw new Error('AUTH_SERVERS_TABLE_NAME is required')
  }

  const preCodesTableName = process.env.PRE_CODES_TABLE_NAME
  if (!preCodesTableName) {
    throw new Error('PRE_CODES_TABLE_NAME is required')
  }

  const authzOAuthClientsTableName = process.env.AUTHZ_OAUTH_CLIENTS_TABLE_NAME
  if (!authzOAuthClientsTableName) {
    throw new Error('AUTHZ_OAUTH_CLIENTS_TABLE_NAME is required')
  }

  const rawPort = process.env.AUTHZ_PORT ?? '8082'
  const port = Number.parseInt(rawPort, 10)
  if (!Number.isFinite(port)) throw new Error(`Invalid AUTHZ_PORT: "${rawPort}"`)

  const store = dynamodbAuthzServerMetadataStore({ tableName: authServersTableName })
  const preAuthorizedCodeStore = dynamodbPreAuthorizedCodeStore({ tableName: preCodesTableName })
  const oauthClientStore = dynamodbAuthzOAuthClientStore({ tableName: authzOAuthClientsTableName })
  const signatureKeyStore = kmsAuthzSignatureKeyStore()
  const { app, context } = createBaseApp(
    createAuthzRouter,
    { port, baseUrl: process.env.AUTHZ_BASE_URL },
    {
      ...options,
      providers: [
        store,
        preAuthorizedCodeStore,
        oauthClientStore,
        signatureKeyStore,
        ...(options?.providers ?? []),
      ],
    }
  )

  async function initialize(baseUrl: string) {
    const authzId = AuthorizationServerIssuer(baseUrl)
    const authzFlow = initializeAuthzFlow(context)

    const existing = await authzFlow.findAuthzServerMetadata(authzId)
    if (existing) {
      console.log('Authz server metadata already exists, skipping initialization')
      // Metadata (DynamoDB) and the signing key (KMS) live in separate stores, so they can drift
      // apart — most often when an environment that ran on the in-memory key store is pointed at
      // KMS. createAuthzServerMetadata rejects an already-registered authz server and cannot
      // repair that, so just make the gap visible.
      // This is a diagnostic, so a KMS failure here (missing permissions, a transient error) must
      // not take the startup down with it: fetch() rethrows everything except a missing key.
      // AuthorizationServerMetadata carries no signing-alg field, so this mirrors the default
      // createAuthzServerMetadata falls back to when no alg option is passed.
      const keyAlg = signatureKeyStore.defaultAlg
      try {
        const publicKey = await signatureKeyStore.fetch(authzId, keyAlg)
        if (!publicKey) {
          console.warn(
            `Authz server metadata exists but no ${keyAlg} key is registered in KMS: signing access tokens will fail`
          )
        }
      } catch (error) {
        console.warn(`Could not check the authz server ${keyAlg} signing key in KMS: ${error}`)
      }
      return
    }

    const samplesDir = join(dirname(fileURLToPath(import.meta.url)), '../../../samples')
    const sampleAuthzMetadata = JSON.parse(
      readFileSync(join(samplesDir, 'authorization_metadata.json'), 'utf-8')
    )
    const metadata = AuthorizationServerMetadata({
      ...sampleAuthzMetadata,
      issuer: baseUrl,
      authorization_endpoint: `${baseUrl}/authorize`,
      token_endpoint: `${baseUrl}/token`,
    })
    await authzFlow.createAuthzServerMetadata(metadata)
    console.log('Authz server metadata initialized')
  }

  return { app, initialize }
}
