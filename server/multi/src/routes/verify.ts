import { Hono } from 'hono'
import { VcknotsContext } from '@trustknots/vcknots'
import {
  VerifierRequestObjectId,
  initializeVerifierFlow,
  VerifierAuthorizationResponse,
  VerifierClientId,
  PresentationExchange,
  VerifierClientIdScheme,
  ClientIdentifier,
} from '@trustknots/vcknots/verifier'
import { randomUUID } from 'node:crypto'
import { handleError } from '../utils/error-handler.js'

export const createVerifierRouter = (context: VcknotsContext, baseUrl: string) => {
  const verifyApp = new Hono()

  const verifierFlow = initializeVerifierFlow(context)

  const canHandleClientIdScheme: VerifierClientIdScheme[] = ['redirect_uri', 'x509_san_dns']
  function validateClientIdScheme(client_id: string): ClientIdentifier {
    if (client_id == null || client_id === '') {
      return 'x509_san_dns:localhost'
    }
    const m = client_id.match(/^([^:]+):(.+)$/)
    const prefix = m?.[1]
    if (!prefix || !canHandleClientIdScheme.includes(prefix as VerifierClientIdScheme)) {
      throw new Error('Invalid client_id format')
    }
    return ClientIdentifier(client_id)
  }

  verifyApp.post('/:verifier/request', async (c) => {
    try {
      const verifierId = VerifierClientId(c.req.param('verifier'))
      type Payload = Record<string, unknown>
      const body: Payload = await c.req.json<Payload>().catch(() => ({}))
      const credentialId = ('credentialId' in body ? body.credentialId : undefined) as
        | string
        | undefined

      if (!credentialId) {
        return c.json(
          {
            error: 'invalid_request',
            error_description: 'credentialId is required.',
          },
          400
        )
      }
      const client_id = validateClientIdScheme(body.client_id as string)

      const query = PresentationExchange({
        presentation_definition: {
          id: randomUUID(),
          name: 'Test Name',
          purpose: 'Test Purpose',
          input_descriptors: [
            {
              id: credentialId,
              format: {
                jwt_vc_json: {
                  proof_type: ['ES256'],
                },
              },
              constraints: {
                fields: [
                  {
                    path: ['$.vc.type'],
                    filter: {
                      type: 'array',
                      contains: {
                        const: 'VerifiableCredential',
                      },
                    },
                  },
                ],
              },
            },
          ],
        },
      })
      const request = await verifierFlow.createAuthzRequest(
        verifierId,
        'vp_token',
        client_id,
        'direct_post',
        query,
        false,
        {
          response_uri: `${baseUrl}/verifiers/${encodeURIComponent(verifierId)}/callback`,
          base_url: `${baseUrl}/verifiers/${encodeURIComponent(verifierId)}`,
        }
      )

      const encoded = Object.entries(request)
        .map(([key, value]) => {
          const encode = value && typeof value === 'object' ? JSON.stringify(value) : String(value)
          return `${encodeURIComponent(key)}=${encodeURIComponent(encode)}`
        })
        .join('&')

      return c.text(`openid4vp://authorize?${encoded}`)
    } catch (err) {
      return c.json(handleError(err), 400)
    }
  })

  verifyApp.post('/:verifier/callback', async (c) => {
    try {
      const verifierId = VerifierClientId(c.req.param('verifier'))
      const json = await c.req.json()

      // Validate it using the AuthorizationResponse
      const authorizationResponse = VerifierAuthorizationResponse(json)

      // Same pattern as server/core: expectedAud = redirect_uri:<this verifier's response_uri>
      const responseUri = `${baseUrl}/verifiers/${encodeURIComponent(verifierId)}/callback`
      await verifierFlow.verifyPresentations(verifierId, authorizationResponse, {
        expectedAud: ClientIdentifier(`redirect_uri:${responseUri}`),
      })

      return c.json({
        message: 'Callback received successfully',
        authorization_response: authorizationResponse,
      })
    } catch (err) {
      return c.json(handleError(err), 400)
    }
  })

  const presentationDefinitionJwtVC = {
    id: randomUUID(),
    name: 'Test Name',
    purpose: 'Test Purpose',
    input_descriptors: [
      {
        id: randomUUID(),
        format: {
          jwt_vc_json: {
            proof_type: ['ES256'],
          },
        },
        constraints: {
          fields: [
            {
              path: ['$.vc.type'],
              filter: {
                type: 'array',
                contains: {
                  const: 'VerifiableCredential',
                },
              },
            },
          ],
        },
      },
    ],
  }

  type RequestObjectShape = {
    query: PresentationExchange
    state: string
    base_url: string
    is_request_uri: boolean
    client_id: ClientIdentifier
  }

  verifyApp.post('/:verifier/request-object', async (c) => {
    const raw = await c.req.text()
    let parsed: unknown = {}
    if (raw.trim()) {
      try {
        parsed = JSON.parse(raw)
      } catch (e) {
        parsed = {}
      }
    }
    const input =
      parsed && typeof parsed === 'object' ? (parsed as Partial<RequestObjectShape>) : {}
    const requestObject: RequestObjectShape = {
      query:
        typeof input.query === 'object' && input.query !== null
          ? input.query
          : {
              presentation_definition: presentationDefinitionJwtVC,
            },
      state:
        typeof input.state === 'string' && input.state.trim() !== ''
          ? input.state
          : randomUUID().replaceAll('-', ''),
      base_url:
        typeof input.base_url === 'string' && input.base_url.trim() !== ''
          ? input.base_url
          : baseUrl,
      is_request_uri: typeof input.is_request_uri === 'boolean' ? input.is_request_uri : true,
      client_id:
        typeof input.client_id === 'string' && input.client_id.trim() !== ''
          ? validateClientIdScheme(input.client_id)
          : 'x509_san_dns:localhost',
    }

    try {
      const verifierId = VerifierClientId(c.req.param('verifier'))
      const request = await verifierFlow.createAuthzRequest(
        verifierId,
        'vp_token',
        requestObject.client_id,
        'direct_post',
        requestObject.query,
        requestObject.is_request_uri,
        {
          state: requestObject.state,
          base_url: baseUrl,
          response_uri: `${baseUrl}/verifiers/${encodeURIComponent(verifierId)}/callback`,
          request_uri: `${baseUrl}/verifiers/${encodeURIComponent(verifierId)}/request.jwt`,
        }
      )
      const encoded = Object.entries(request)
        .map(([key, value]) => {
          const encode = value && typeof value === 'object' ? JSON.stringify(value) : String(value)
          return `${encodeURIComponent(key)}=${encodeURIComponent(encode)}`
        })
        .join('&')

      return c.text(`openid4vp://authorize?${encoded}`)
    } catch (err) {
      return c.json(handleError(err), 400)
    }
  })

  verifyApp.get('/:verifier/request.jwt/:request-object-Id', async (c) => {
    try {
      const verifierId = VerifierClientId(c.req.param('verifier'))
      const requestObjectId = VerifierRequestObjectId(c.req.param('request-object-Id'))
      const jar = await verifierFlow.findRequestObject(verifierId, requestObjectId)
      return c.body(jar, 200, {
        'Content-Type': 'application/oauth-authz-req+jwt',
      })
    } catch (err) {
      return c.json(handleError(err), 400)
    }
  })

  return verifyApp
}
