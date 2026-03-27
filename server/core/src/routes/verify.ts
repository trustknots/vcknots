import { Hono } from 'hono'
import { VcknotsContext } from '@trustknots/vcknots'
import {
  VerifierClientIdScheme,
  VerifierRequestObjectId,
  initializeVerifierFlow,
  VerifierAuthorizationResponse,
  VerifierClientId,
  ClientIdentifier,
  PresentationExchange,
} from '@trustknots/vcknots/verifier'
import { randomUUID } from 'node:crypto'
import { handleError } from '../utils/error-handler.js'
import { createDirectPostVpAudTransactionStore } from '../utils/direct-post-vp-aud-transaction-store.js'

export const createVerifierRouter = (context: VcknotsContext, baseUrl: string) => {
  const verifyApp = new Hono()

  const verifierFlow = initializeVerifierFlow(context)
  const vpAudTx = createDirectPostVpAudTransactionStore()

  type PayloadResult =
    | { ok: true; payload: Partial<VerifierAuthorizationResponse> }
    | { ok: false; error: { error: string; error_description: string } }
  const normalizeContentType = (value: string) => value.split(';')[0]?.trim().toLowerCase() ?? ''
  const parseFormPayload = (form: FormData): PayloadResult => {
    const payload: Partial<VerifierAuthorizationResponse> = {}
    const presentationSubmission = form.get('presentation_submission')
    if (typeof presentationSubmission === 'string' && presentationSubmission.trim()) {
      try {
        payload.presentation_submission = JSON.parse(presentationSubmission)
      } catch {
        return {
          ok: false,
          error: {
            error: 'invalid_request',
            error_description: 'presentation_submission must be JSON',
          },
        }
      }
    }
    const vpToken = form.getAll('vp_token').filter((v): v is string => typeof v === 'string')
    payload.vp_token =
      vpToken.length === 0 ? undefined : vpToken.length === 1 ? vpToken[0] : vpToken
    const state = form.get('state')
    if (typeof state === 'string') {
      payload.state = state
    }
    return { ok: true, payload }
  }

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

  verifyApp.post('/request', async (c) => {
    try {
      const verifierId = VerifierClientId(baseUrl)
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
      const state =
        typeof body.state === 'string' && body.state.trim() !== '' ? body.state.trim() : undefined
      if (state === undefined) {
        return c.json(
          {
            error: 'invalid_request',
            error_description: 'state is required.',
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
          response_uri: `${baseUrl}/callback`,
          base_url: baseUrl,
        }
      )
      const registered = vpAudTx.register(client_id, state)
      if (!registered.ok) {
        return c.json(registered.error, 400)
      }
      console.log('[verify] direct_post transaction_id:', registered.transactionId)

      const encoded = Object.entries({ ...request, state })
        .map(([key, value]) => {
          const encode = value && typeof value === 'object' ? JSON.stringify(value) : String(value)
          return `${encodeURIComponent(key)}=${encodeURIComponent(encode)}`
        })
        .join('&')

      return c.text(`openid4vp://authorize?${encoded}`)
    } catch (err) {
      const errorResponse = handleError(err)
      const status = errorResponse.error === 'internal_server_error' ? 500 : 400
      return c.json(errorResponse, status)
    }
  })

  // Receive the vp_token from the request and verify it
  verifyApp.post('/callback', async (c) => {
    try {
      const verifierId = VerifierClientId(baseUrl)
      const contentType = normalizeContentType(c.req.header('content-type') ?? '')

      if (contentType !== 'application/x-www-form-urlencoded') {
        return c.json(
          {
            error: 'invalid_request',
            error_description: 'content-type must be application/x-www-form-urlencoded',
          },
          400
        )
      }

      const formData = await c.req.formData()
      const parsed = parseFormPayload(formData)

      if (!parsed.ok) {
        return c.json(parsed.error, 400)
      }

      // Validate it using the AuthorizationResponse
      const authorizationResponse = VerifierAuthorizationResponse(parsed.payload)

      const audResolved = vpAudTx.resolveExpectedAudFromWalletState(authorizationResponse.state)
      if (!audResolved.ok) {
        return c.json(audResolved.error, 400)
      }
      console.log('[verify] expectedAud:', audResolved.aud)
      const vpPayload = await verifierFlow.verifyPresentations(verifierId, authorizationResponse, {
        expectedAud: audResolved.aud,
      })
      if (authorizationResponse.state != null && authorizationResponse.state !== '') {
        vpAudTx.consume(audResolved.transactionId, authorizationResponse.state)
      }
      console.log('Verified VP Payload:', vpPayload)
      return c.json({ redirect_uri: `${baseUrl}/verified` }, 200)
    } catch (err) {
      const errorResponse = handleError(err)
      console.log('error Response:', errorResponse)
      const status = errorResponse.error === 'internal_server_error' ? 500 : 400
      return c.json(errorResponse, status)
    }
  })

  verifyApp.post('/callback-kbjwt', async (c) => {
    try {
      console.log('callback-kbjwt')
      const verifierId = VerifierClientId(baseUrl)
      const contentType = normalizeContentType(c.req.header('content-type') ?? '')

      if (contentType !== 'application/x-www-form-urlencoded') {
        return c.json(
          {
            error: 'invalid_request',
            error_description: 'content-type must be application/x-www-form-urlencoded',
          },
          400
        )
      }
      const formData = await c.req.formData()
      const parsed = parseFormPayload(formData)
      if (!parsed.ok) {
        return c.json(parsed.error, 400)
      }

      // Validate it using the AuthorizationResponse
      const authorizationResponse = VerifierAuthorizationResponse(parsed.payload)
      const audResolved = vpAudTx.resolveExpectedAudFromWalletState(authorizationResponse.state)
      if (!audResolved.ok) {
        return c.json(audResolved.error, 400)
      }
      console.log('[verify] expectedAud (callback-kbjwt):', audResolved.aud)
      const vpPayload = await verifierFlow.verifyPresentations(verifierId, authorizationResponse, {
        expectedAud: audResolved.aud,
        isKbJwt: true,
      })
      if (authorizationResponse.state != null && authorizationResponse.state !== '') {
        vpAudTx.consume(audResolved.transactionId, authorizationResponse.state)
      }
      console.log('Verified KBJWT VP Payload:', vpPayload)
      return c.json({ redirect_uri: `${baseUrl}/verified` }, 200)
    } catch (err) {
      const errorResponse = handleError(err)
      console.log('error Response:', errorResponse)
      const status = errorResponse.error === 'internal_server_error' ? 500 : 400
      return c.json(errorResponse, status)
    }
  })

  // Create the request in JAR format
  type RequestObjectShape = {
    query: PresentationExchange
    state: string
    base_url: string
    is_request_uri: boolean
    client_id: ClientIdentifier
    is_transaction_data: boolean
    response_uri?: string
  }
  verifyApp.post('/request-object', async (c) => {
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
    const raw = await c.req.text()
    let parsed: unknown = {}
    if (raw.trim()) {
      try {
        parsed = JSON.parse(raw)
      } catch (e) {
        return c.json(
          { error: 'invalid_request', error_description: 'Request body must be valid JSON' },
          400
        )
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
      is_transaction_data:
        typeof input.is_transaction_data === 'boolean' ? input.is_transaction_data : false,
      response_uri:
        typeof input.response_uri === 'string' && input.response_uri.trim() !== ''
          ? input.response_uri
          : undefined,
      client_id:
        typeof input.client_id === 'string' && input.client_id.trim() !== ''
          ? validateClientIdScheme(input.client_id)
          : 'x509_san_dns:localhost',
    }

    try {
      const verifierId = VerifierClientId(baseUrl)
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
          response_uri: requestObject.response_uri ?? `${baseUrl}/callback`,
          request_uri: `${baseUrl}/request.jwt`,
          ...(requestObject.is_transaction_data
            ? { transaction_data: { type: 'sample_type' } }
            : {}),
        }
      )
      const registered = vpAudTx.register(requestObject.client_id, requestObject.state)
      if (!registered.ok) {
        return c.json(registered.error, 400)
      }
      console.log('[verify] direct_post transaction_id:', registered.transactionId)
      // const params = requestObject.is_request_uri
      //   ? request
      //   : { ...request, state: requestObject.state }
      const encoded = Object.entries(request)
        .map(([key, value]) => {
          const encode = value && typeof value === 'object' ? JSON.stringify(value) : String(value)
          return `${encodeURIComponent(key)}=${encodeURIComponent(encode)}`
        })
        .join('&')

      return c.text(`openid4vp://authorize?${encoded}`)
    } catch (err) {
      const errorResponse = handleError(err)
      const status = errorResponse.error === 'internal_server_error' ? 500 : 400
      return c.json(errorResponse, status)
    }
  })

  verifyApp.get('/request.jwt/:request-object-Id', async (c) => {
    try {
      console.log('request-object-Id:', c.req.param('request-object-Id'))
      const verifierId = VerifierClientId(baseUrl)
      const requestObjectId = VerifierRequestObjectId(c.req.param('request-object-Id'))
      const jar = await verifierFlow.findRequestObject(verifierId, requestObjectId)
      return c.body(jar, 200, {
        'Content-Type': 'application/oauth-authz-req+jwt',
      })
    } catch (err) {
      const errorResponse = handleError(err)
      const status = errorResponse.error === 'internal_server_error' ? 500 : 400
      return c.json(errorResponse, status)
    }
  })

  verifyApp.get('/verified', async (c) => {
    console.log('Verified received from get request')
    return c.json({ message: 'DONE!!' }, 200)
  })

  verifyApp.get('/presentation-transaction/:transactionId', async (c) => {
    const transactionId = c.req.param('transactionId')?.trim() ?? ''
    if (transactionId === '') {
      return c.json(
        { error: 'invalid_request', error_description: 'transactionId is required' },
        400
      )
    }
    const result = vpAudTx.getById(transactionId)
    if (result.kind === 'not_found') {
      return c.json(
        { error: 'not_found', error_description: 'transaction_id is unknown or already removed' },
        404
      )
    }
    if (result.kind === 'expired') {
      return c.json({ error: 'not_found', error_description: 'transaction_id has expired' }, 404)
    }
    return c.json({
      transaction_id: transactionId,
      state: result.state,
      client_id: result.clientId,
      expires_at: result.expiresAt,
    })
  })

  verifyApp.delete('/presentation-transaction/:transactionId', async (c) => {
    const transactionId = c.req.param('transactionId')?.trim() ?? ''
    if (transactionId === '') {
      return c.json(
        { error: 'invalid_request', error_description: 'transactionId is required' },
        400
      )
    }
    const result = vpAudTx.deleteById(transactionId)
    if (!result.ok) {
      return c.json(
        { error: 'not_found', error_description: 'transaction_id is unknown or already removed' },
        404
      )
    }
    return c.json({ ok: true }, 200)
  })

  return verifyApp
}
