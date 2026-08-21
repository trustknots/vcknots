import { readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  dynamodbNonceStore,
  dynamodbRequestObjectStore,
  dynamodbVerifierMetadataStore,
  kmsVerifierSignatureKeyStore,
  secretsManagerVerifierCertificateStore,
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
  const certificateStore = secretsManagerVerifierCertificateStore({
    secretPrefix: process.env.VERIFIER_CERTIFICATE_SECRET_PREFIX,
  })
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
        certificateStore,
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
      // Metadata (DynamoDB) and the signing key (KMS) / certificate (Secrets Manager) live in
      // separate stores, so they can drift apart — most often when an environment that ran on
      // the in-memory stores is pointed at AWS. createVerifierMetadata rejects an
      // already-registered verifier and cannot repair that, so just make the gap visible.
      // This is a diagnostic, so a KMS or Secrets Manager failure here (missing permissions, a
      // transient error) must not take the startup down with it: fetch() rethrows everything
      // except a missing key or certificate.
      const keyAlg = existing.authorization_signed_response_alg ?? signatureKeyStore.defaultAlg
      try {
        const publicKey = await signatureKeyStore.fetch(verifierId, keyAlg)
        if (!publicKey) {
          console.warn(
            `Verifier metadata exists but no ${keyAlg} key is registered in KMS: signing authorization requests will fail`,
          )
        }
      } catch (error) {
        console.warn(`Could not check the verifier ${keyAlg} signing key in KMS: ${error}`)
      }
      try {
        const certificate = await verifierFlow.findVerifierCertificate(verifierId)
        if (!certificate || certificate.length === 0) {
          console.warn(
            'Verifier metadata exists but no certificate is registered: x509_san_dns requests will fail',
          )
        }
      } catch (error) {
        console.warn(`Could not check the verifier certificate in Secrets Manager: ${error}`)
      }
      return
    }

    const samplesDir = join(dirname(fileURLToPath(import.meta.url)), '../../../samples')
    const sampleVerifierMetadata = JSON.parse(readFileSync(join(samplesDir, 'verifier_metadata.json'), 'utf-8'))

    // Registering with a certificate is what populates the certificate store; without it the
    // verifier cannot sign JAR requests for x509_san_dns / x509_san_uri client ids.
    const option = {
      privateKey: readPem('PRIVATE_KEY', 'PRIVATE_KEY_PATH', join(samplesDir, DEFAULT_PRIVATE_KEY)),
      certificate: readPem('CERTIFICATE', 'CERTIFICATE_PATH', join(samplesDir, DEFAULT_CERTIFICATE)),
      format: 'pem',
      alg: 'ES256',
    } as const

    const metadata = VerifierMetadata(sampleVerifierMetadata)
    await verifierFlow.createVerifierMetadata(verifierId, metadata, option)
    console.log('Verifier metadata and certificate initialized')
  }

  return { app, initialize }
}

const DEFAULT_PRIVATE_KEY = 'certificate-openid-test/private_key_openid.pem'
const DEFAULT_CERTIFICATE = 'certificate-openid-test/certificate_openid.pem'

/** Reads a PEM from an inline env var, a path env var, or the bundled sample, in that order. */
function readPem(valueEnv: string, pathEnv: string, defaultPath: string): string {
  const inline = process.env[valueEnv]?.replace(/\\n/g, '\n')
  if (inline) return inline
  const path = process.env[pathEnv]
  return readFileSync(path ? resolve(path) : defaultPath, 'utf-8')
}
