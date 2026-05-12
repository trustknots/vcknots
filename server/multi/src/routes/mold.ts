import {
  VcknotsContext,
  parseVerifierClientId,
  parseCredentialIssuerMetadata,
  parseAuthorizationServerMetadata,
  parseVerifierMetadata,
} from '@trustknots/vcknots'
import { initializeIssuerFlow } from '@trustknots/vcknots/issuer'
import { initializeAuthzFlow } from '@trustknots/vcknots/authz'
import { initializeVerifierFlow } from '@trustknots/vcknots/verifier'
import { Hono } from 'hono'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { readFileSync } from 'node:fs'
import { handleError } from '../utils/error-handler.js'

export const createMoldRouter = (context: VcknotsContext, baseUrl: string) => {
  const moldApp = new Hono()

  const issuerFlow = initializeIssuerFlow(context)
  const authzFlow = initializeAuthzFlow(context)
  const verifierFlow = initializeVerifierFlow(context)

  moldApp.post('/issuers', async (c) => {
    try {
      const json = await c.req.json()
      const issuer = parseCredentialIssuerMetadata(json)
      await issuerFlow.createIssuerMetadata(issuer) // Receive the entire domain
      return c.json({ message: 'OK' })
    } catch (err) {
      return c.json(handleError(err), 400)
    }
  })

  moldApp.post('/authorization', async (c) => {
    try {
      const json = await c.req.json()
      const authz = parseAuthorizationServerMetadata(json)
      await authzFlow.createAuthzServerMetadata(authz) // Receive the entire domain
      return c.json({ message: 'OK' })
    } catch (err) {
      return c.json(handleError(err), 400)
    }
  })

  moldApp.post('/verifiers/:verifier/metadata', async (c) => {
    try {
      const verifierId = parseVerifierClientId(c.req.param('verifier'))
      const json = await c.req.json()
      const metadata = parseVerifierMetadata(json)

      // Provisionally create it using the default (certificate_openid.pem)
      const __dirname = dirname(fileURLToPath(import.meta.url))
      const privateKeyPath = join(
        __dirname,
        '../../../',
        'samples/certificate-openid-test/private_key_openid.pem'
      )
      const certificatePath = join(
        __dirname,
        '../../../',
        'samples/certificate-openid-test/certificate_openid.pem'
      )
      const option = {
        privateKey: readFileSync(privateKeyPath, 'utf-8'),
        certificate: readFileSync(certificatePath, 'utf-8'),
        format: 'pem',
        alg: 'ES256',
      } as const

      await verifierFlow.createVerifierMetadata(verifierId, metadata, option)
      return c.json({ message: 'OK' })
    } catch (err) {
      return c.json(handleError(err), 400)
    }
  })

  return moldApp
}
