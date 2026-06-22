import 'dotenv/config'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { CredentialIssuer, CredentialIssuerMetadata, initializeIssuerFlow } from '@trustknots/vcknots/issuer'
import { createIssuerApp } from '../apps/create-issuer-app.js'
import { serveApp } from './serve.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const samplesDir = join(__dirname, '../../../samples')

process.env.BASE_URL ??= 'http://localhost:8081'

const { app, context, baseUrl } = createIssuerApp()

async function initializeIssuerMetadata() {
  const issuerFlow = initializeIssuerFlow(context)

  const raw = JSON.parse(readFileSync(join(samplesDir, 'issuer_metadata.json'), 'utf-8'))
  const metadata = CredentialIssuerMetadata({
    ...raw,
    credential_issuer: CredentialIssuer(baseUrl),
    authorization_servers: [baseUrl],
    credential_endpoint: `${baseUrl}/credentials`,
    deferred_credential_endpoint: `${baseUrl}/deferred_credential`,
    nonce_endpoint: `${baseUrl}/nonce`,
  })

  try {
    const existing = await issuerFlow.findIssuerMetadata(metadata.credential_issuer)
    if (existing) {
      console.log('Issuer metadata already exists, skipping initialization')
      return
    }

    await issuerFlow.createIssuerMetadata(metadata)
    console.log('Issuer metadata initialized')
  } catch (error) {
    console.error('Error initializing issuer metadata:', error)
    throw error
  }
}

initializeIssuerMetadata()
  .then(() => serveApp(app, 'Issuer', 8081))
  .catch((error) => {
    console.error('Fatal: Failed to initialize issuer metadata', error)
    process.exit(1)
  })
