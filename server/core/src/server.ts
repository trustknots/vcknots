import { readFileSync } from 'node:fs'
import { serve } from '@hono/node-server'
import { initializeContext } from '@trustknots/vcknots'
import type { VcknotsOptions } from '@trustknots/vcknots'
import {
  AuthorizationServerIssuer,
  AuthorizationServerMetadata,
  initializeAuthzFlow,
} from '@trustknots/vcknots/authz'
import {
  CredentialIssuer,
  CredentialIssuerMetadata,
  initializeIssuerFlow,
} from '@trustknots/vcknots/issuer'
import {
  initializeVerifierFlow,
  VerifierClientId,
  VerifierMetadata,
} from '@trustknots/vcknots/verifier'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createApp } from './app.js'

export const createServer = (options?: VcknotsOptions) => {
  const __dirname = dirname(fileURLToPath(import.meta.url))
  const samplesDir = join(__dirname, '../../samples')
  const issuerMetadataConfigRaw = JSON.parse(
    readFileSync(join(samplesDir, 'issuer_metadata.json'), 'utf-8')
  )
  const authorizationMetadataConfigRaw = JSON.parse(
    readFileSync(join(samplesDir, 'authorization_metadata.json'), 'utf-8')
  )
  const verifierMetadataConfigRaw = JSON.parse(
    readFileSync(join(samplesDir, 'verifier_metadata.json'), 'utf-8')
  )

  const issuerMetadataConfig = CredentialIssuerMetadata(issuerMetadataConfigRaw)
  const authorizationMetadataConfig = AuthorizationServerMetadata(authorizationMetadataConfigRaw)
  const verifierMetadataConfig = VerifierMetadata(verifierMetadataConfigRaw)

  const context = initializeContext({
    ...options,
    debug: process.env.NODE_ENV !== 'production',
  })

  const issuerFlow = initializeIssuerFlow(context)
  const authzFlow = initializeAuthzFlow(context)
  const verifierFlow = initializeVerifierFlow(context)

  const baseUrl = process.env.BASE_URL ?? 'http://localhost:8080'
  const app = createApp(context, baseUrl)

  async function main() {
    if (!(await initializeVerifierMetadata(baseUrl, verifierMetadataConfig))) {
      throw new Error('Failed to initialize verifier metadata')
    }

    issuerMetadataConfig.credential_issuer = CredentialIssuer(baseUrl)
    issuerMetadataConfig.authorization_servers = [baseUrl]
    issuerMetadataConfig.credential_endpoint = `${baseUrl}/credentials`
    issuerMetadataConfig.batch_credential_endpoint = `${baseUrl}/batch_credential`
    issuerMetadataConfig.deferred_credential_endpoint = `${baseUrl}/deferred_credential`
    if (!(await initializeIssuerMetadata(issuerMetadataConfig))) {
      throw new Error('Failed to initialize issuer metadata')
    }

    authorizationMetadataConfig.issuer = AuthorizationServerIssuer(baseUrl)
    authorizationMetadataConfig.authorization_endpoint = `${baseUrl}/authorize`
    authorizationMetadataConfig.token_endpoint = `${baseUrl}/token`
    if (!(await initializeAuthzMetadata(authorizationMetadataConfig))) {
      throw new Error('Failed to initialize authz metadata')
    }

    serve({ fetch: app.fetch, port: Number.parseInt(process.env.PORT ?? '8080') }, async () => {
      console.log(`Server is running on ${baseUrl}`)
    })
  }

  main().catch((error) => {
    console.error('Fatal: Server startup failed', error)
    process.exit(1)
  })

  async function initializeIssuerMetadata(issuerMetadata: CredentialIssuerMetadata) {
    try {
      const issuer = await issuerFlow.findIssuerMetadata(issuerMetadata.credential_issuer)
      if (issuer) {
        console.log('Issuer metadata already exists, skipping initialization')
        return true
      }

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
      const authzServer = await authzFlow.findAuthzServerMetadata(authzMetadata.issuer)
      if (authzServer) {
        console.log('Authz metadata already exists, skipping initialization')
        return true
      }

      await authzFlow.createAuthzServerMetadata(authzMetadata)
      console.log('Authz metadata initialized')
      return true
    } catch (error) {
      console.error('Error initializing authz metadata:', error)
      return false
    }
  }

  async function initializeVerifierMetadata(verifierId: string, metadata: VerifierMetadata) {
    try {
      const clientId = VerifierClientId(verifierId)

      const verifier = await verifierFlow.findVerifierMetadata(clientId)
      if (verifier) {
        console.log('Verifier metadata already exists, skipping initialization')
        return true
      }

      const verifierCertificate = await verifierFlow.findVerifierCertificate(clientId)
      if (verifierCertificate && verifierCertificate.length > 0) {
        console.log('Verifier certificate already exists, skipping initialization')
        return true
      }

      const defaultPrivateKeyPath = join(
        __dirname,
        '../../samples/certificate-openid-test/private_key_openid.pem'
      )
      const defaultCertPath = join(
        __dirname,
        '../../samples/certificate-openid-test/certificate_openid.pem'
      )

      const privateKeyPath = process.env.PRIVATE_KEY_PATH
        ? resolve(process.env.PRIVATE_KEY_PATH)
        : defaultPrivateKeyPath
      const certificatePath = process.env.CERTIFICATE_PATH
        ? resolve(process.env.CERTIFICATE_PATH)
        : defaultCertPath

      const privateKeyEnv = process.env.PRIVATE_KEY?.replace(/\\n/g, '\n')
      const certificateEnv = process.env.CERTIFICATE?.replace(/\\n/g, '\n')
      const privateKey = privateKeyEnv ?? readFileSync(privateKeyPath, 'utf-8')
      const certificate = certificateEnv ?? readFileSync(certificatePath, 'utf-8')

      const option = { privateKey, certificate, format: 'pem', alg: 'ES256' } as const
      await verifierFlow.createVerifierMetadata(clientId, metadata, option)

      console.log(`Verifier metadata initialized for ${clientId}`)
      return true
    } catch (error) {
      console.error('Error initializing verifier metadata:', error)
      return false
    }
  }
}
