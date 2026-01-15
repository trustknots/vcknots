import { serve } from '@hono/node-server'
import { initializeContext } from '@trustknots/vcknots'
import {
  CredentialIssuer,
  CredentialIssuerMetadata,
  initializeIssuerFlow,
} from '@trustknots/vcknots/issuer'
import {
  initializeVerifierFlow,
  VerifierMetadata,
  VerifierClientId,
} from '@trustknots/vcknots/verifier'
import {
  AuthorizationServerIssuer,
  initializeAuthzFlow,
  AuthorizationServerMetadata,
} from '@trustknots/vcknots/authz'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { readFileSync } from 'node:fs'

import issuerMetadataConfigRaw from '../../samples/issuer_metadata.json' with { type: 'json' }
import authorizationMetadataConfigRaw from '../../samples/authorization_metadata.json' with {
  type: 'json',
}
import verifierMetadataConfigRaw from '../../samples/verifier_metadata.json' with { type: 'json' }
import { createApp } from './app.js'

// Metadata validation
const issuerMetadataConfig = CredentialIssuerMetadata(issuerMetadataConfigRaw)
const authorizationMetadataConfig = AuthorizationServerMetadata(authorizationMetadataConfigRaw)
const verifierMetadataConfig = VerifierMetadata(verifierMetadataConfigRaw)

// Create VcknotsContext
export const context = initializeContext({
  debug: process.env.NODE_ENV !== 'production',
})

// Create each Flow instance
const issuerFlow = initializeIssuerFlow(context)
const authzFlow = initializeAuthzFlow(context)
const verifierFlow = initializeVerifierFlow(context)

// Reference:
// const vk = vcknots({
// Variable infrastructure points and spec group extension points
// providers: [kms() /* key operations */, firestore() /* data store */],
// Variable processing sequence points
// extensions: [trace()],
//   debug: process.env.NODE_ENV !== "production",
// });

const baseUrl = process.env.BASE_URL ?? 'http://localhost:8080'

const app = createApp(context, baseUrl)

serve({ fetch: app.fetch, port: Number.parseInt(process.env.PORT ?? '8080') }, async (info) => {
  console.log(`Server is running on http://localhost:${info.port}`)

  // Execute initialization (using the default settings)
  // By default, issuerId, authorizationServerId, and verifierId use the baseUrl
  const issuerURL = `${baseUrl}/issuers/${encodeURIComponent(baseUrl)}`
  const authzURL = `${baseUrl}/authorizations/${encodeURIComponent(baseUrl)}`
  await initializeVerifierMetadata(baseUrl, verifierMetadataConfig)

  issuerMetadataConfig.credential_issuer = CredentialIssuer(baseUrl)
  issuerMetadataConfig.authorization_servers = [authzURL]
  issuerMetadataConfig.credential_endpoint = `${issuerURL}/credentials`
  issuerMetadataConfig.batch_credential_endpoint = `${issuerURL}/batch_credential`
  issuerMetadataConfig.deferred_credential_endpoint = `${issuerURL}/deferred_credential`
  await initializeIssuerMetadata(issuerMetadataConfig)

  authorizationMetadataConfig.issuer = AuthorizationServerIssuer(baseUrl)
  authorizationMetadataConfig.authorization_endpoint = `${authzURL}/authorize`
  authorizationMetadataConfig.token_endpoint = `${authzURL}/token`
  await initializeAuthzMetadata(authorizationMetadataConfig)
})

async function initializeIssuerMetadata(issuerMetadata: CredentialIssuerMetadata) {
  try {
    await issuerFlow.createIssuerMetadata(issuerMetadata)
    console.log('Issuer metadata initialized')
    return true
  } catch (error) {
    console.error('Error initializing issuer metadata:', error)
    return false
  }
}

async function initializeAuthzMetadata(authzMetadata: AuthorizationServerMetadata) {
  try {
    await authzFlow.createAuthzServerMetadata(authzMetadata)
    console.log('Authz metadata initialized')
    return true
  } catch (error) {
    console.error('Error initializing authz metadata:', error)
    return false
  }
}

/**
 * Initialize the metadata when the server starts
 * @param verifierId
 * @param metadata defaultVerifierMetadata
 * @returns boolean
 */
async function initializeVerifierMetadata(verifierId: string, metadata: VerifierMetadata) {
  try {
    const clientId = VerifierClientId(verifierId)

    const __dirname = dirname(fileURLToPath(import.meta.url))
    const privateKeyPath = join(
      __dirname,
      '../../',
      'samples/certificate-openid-test/private_key_openid.pem'
    )
    const certificatePath = join(
      __dirname,
      '../../',
      'samples/certificate-openid-test/certificate_openid.pem'
    )
    const option = {
      privateKey: readFileSync(privateKeyPath, 'utf-8'),
      certificate: readFileSync(certificatePath, 'utf-8'),
      format: 'pem',
      alg: 'ES256',
    } as const

    await verifierFlow.createVerifierMetadata(clientId, metadata, option)

    console.log(`Verifier metadata initialized for ${clientId}`)
    return true
  } catch (error) {
    console.error('Error initializing verifier metadata:', error)
    return false
  }
}

// Notes
// Verifier behavior: metadata is initialized when the server starts.
// If you want to separate metadata for sd-jwt or others, switch it accordingly.

// Authorization request
// 1. /verifiers/:verifier/request            (traditional endpoint)
// 2. /verifiers/:verifier/request-object     (uses JAR)
