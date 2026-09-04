import { randomUUID } from 'node:crypto'
import { VcknotsContext } from '@trustknots/vcknots'
import {
  ClientIdentifier,
  VerifierAuthorizationResponse,
  VerifierClientId,
  VerifierClientIdPrefix,
  VerifierRequestObjectId,
  initializeVerifierFlow,
} from '@trustknots/vcknots/verifier'
import { Hono } from 'hono'
import { createDirectPostVpAudTransactionStore } from '../utils/direct-post-vp-aud-transaction-store.js'
import { handleError } from '../utils/error-handler.js'

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
    const vpTokenRaw = form.get('vp_token')
    if (typeof vpTokenRaw === 'string' && vpTokenRaw.trim()) {
      let parsedVpToken: unknown
      try {
        parsedVpToken = JSON.parse(vpTokenRaw)
      } catch {
        return {
          ok: false,
          error: {
            error: 'invalid_request',
            error_description: 'vp_token must be a JSON object',
          },
        }
      }
      if (
        typeof parsedVpToken !== 'object' ||
        parsedVpToken === null ||
        Array.isArray(parsedVpToken)
      ) {
        return {
          ok: false,
          error: {
            error: 'invalid_request',
            error_description: 'vp_token must be a JSON object',
          },
        }
      }
      payload.vp_token = parsedVpToken as VerifierAuthorizationResponse['vp_token']
    }
    const state = form.get('state')
    if (typeof state === 'string') {
      payload.state = state
    }
    return { ok: true, payload }
  }

  const canHandleClientIdScheme: VerifierClientIdPrefix[] = ['redirect_uri', 'x509_san_dns']
  function validateClientIdScheme(client_id: string): ClientIdentifier {
    if (client_id == null || client_id === '') {
      return 'x509_san_dns:localhost'
    }
    const m = client_id.match(/^([^:]+):(.+)$/)
    const prefix = m?.[1]
    if (!prefix || !canHandleClientIdScheme.includes(prefix as VerifierClientIdPrefix)) {
      throw new Error('Invalid client_id format')
    }
    return ClientIdentifier(client_id)
  }

  verifyApp.post('/request', async (c) => {
    try {
      const verifierId = VerifierClientId(baseUrl)
      type Payload = Record<string, unknown>
      const body: Payload = await c.req.json<Payload>().catch(() => ({}))

      const credentialId =
        typeof body.credentialId === 'string' && body.credentialId.trim() !== ''
          ? body.credentialId
          : undefined

      if (!credentialId) {
        return c.json(
          {
            error: 'invalid_request',
            error_description: 'credentialId must be a non-empty string.',
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
      const client_id = validateClientIdScheme(
        (body.client_id as string) ?? 'redirect_uri:localhost'
      )

      const query = {
        dcql_query: {
          credentials: [
            {
              id: randomUUID(),
              format: 'jwt_vc_json',
              meta: {
                type_values: [[credentialId]],
              },
            },
          ],
        },
      }

      const reserved = vpAudTx.reserve(state)
      if (!reserved.ok) {
        return c.json(reserved.error, 400)
      }
      const { request, transactionId: verifierTxId } = await verifierFlow
        .createAuthzRequest(verifierId, 'vp_token', client_id, 'direct_post', query, false, {
          state,
          response_uri: `${baseUrl}/callback`,
          base_url: baseUrl,
        })
        .catch((err: unknown) => {
          vpAudTx.consume(state)
          throw err
        })
      vpAudTx.register(state, verifierTxId)
      console.log('[verify] direct_post transaction_id:', verifierTxId)

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

      const formData = await c.req.formData().catch(() => null)
      if (!formData) {
        return c.json(
          {
            error: 'invalid_request',
            error_description: 'Request body must be a valid form data.',
          },
          400
        )
      }
      const parsed = parseFormPayload(formData)

      if (!parsed.ok) {
        return c.json(parsed.error, 400)
      }

      const authorizationResponse = VerifierAuthorizationResponse(parsed.payload)

      const resolved = vpAudTx.resolve(authorizationResponse.state)
      if (!resolved.ok) {
        return c.json(resolved.error, 400)
      }
      const vpPayload = await verifierFlow.verifyPresentations(
        authorizationResponse,
        resolved.transactionId
      )
      vpAudTx.consume(authorizationResponse.state ?? '')
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
      const formData = await c.req.formData().catch(() => null)
      if (!formData) {
        return c.json(
          {
            error: 'invalid_request',
            error_description: 'Request body must be a valid form data.',
          },
          400
        )
      }
      const parsed = parseFormPayload(formData)
      if (!parsed.ok) {
        return c.json(parsed.error, 400)
      }

      const authorizationResponse = VerifierAuthorizationResponse(parsed.payload)
      const resolved = vpAudTx.resolve(authorizationResponse.state)
      if (!resolved.ok) {
        return c.json(resolved.error, 400)
      }
      const vpPayload = await verifierFlow.verifyPresentations(
        authorizationResponse,
        resolved.transactionId,
        { isKbJwt: true }
      )
      vpAudTx.consume(authorizationResponse.state ?? '')
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
  type AuthzQueryInput = Parameters<typeof verifierFlow.createAuthzRequest>[4]
  type RequestObjectShape = {
    query: AuthzQueryInput
    state: string
    base_url: string
    is_request_uri: boolean
    client_id: ClientIdentifier
    is_transaction_data: boolean
    response_uri?: string
  }
  type RequestObjectInput = Partial<
    Omit<RequestObjectShape, 'query' | 'client_id'> & {
      query: unknown
      client_id: string
    }
  >
  verifyApp.post('/request-object', async (c) => {
    // TODO: Sample
    const dcqlQuery = {
      dcql_query: {
        credentials: [
          {
            id: randomUUID(),
            format: 'jwt_vc_json',
            meta: {
              type_values: [['VerifiableCredential']],
            },
          },
        ],
      },
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
    const input = parsed && typeof parsed === 'object' ? (parsed as RequestObjectInput) : {}
    const requestObject: RequestObjectShape = {
      query:
        typeof input.query === 'object' && input.query !== null && !Array.isArray(input.query)
          ? input.query
          : dcqlQuery,
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

    let reserved: ReturnType<typeof vpAudTx.reserve> | undefined
    try {
      reserved = vpAudTx.reserve(requestObject.state)
      if (!reserved.ok) {
        return c.json(reserved.error, 400)
      }
      const verifierId = VerifierClientId(baseUrl)
      const { request, transactionId: verifierTxId } = await verifierFlow.createAuthzRequest(
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
      vpAudTx.register(requestObject.state, verifierTxId)
      console.log('[verify] direct_post transaction_id:', verifierTxId)
      const encoded = Object.entries(request)
        .map(([key, value]) => {
          const encode = value && typeof value === 'object' ? JSON.stringify(value) : String(value)
          return `${encodeURIComponent(key)}=${encodeURIComponent(encode)}`
        })
        .join('&')

      return c.text(`openid4vp://authorize?${encoded}`)
    } catch (err) {
      if (reserved?.ok) {
        vpAudTx.consume(requestObject.state)
      }
      const errorResponse = handleError(err)
      const status = errorResponse.error === 'internal_server_error' ? 500 : 400
      return c.json(errorResponse, status)
    }
  })

  verifyApp.get('/request.jwt/:request-object-Id', async (c) => {
    try {
      console.log('request-object-Id:', c.req.param('request-object-Id'))
      const verifierId = VerifierClientId(baseUrl)
      const parseResult = VerifierRequestObjectId.schema.safeParse(c.req.param('request-object-Id'))
      if (!parseResult.success) {
        return c.json(
          {
            error: 'invalid_request',
            error_description: 'Invalid request-object-Id parameter.',
          },
          400
        )
      }
      const requestObjectId = parseResult.data
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
    try {
      const result = await verifierFlow.getTransaction(transactionId)
      return c.json({
        transaction_id: transactionId,
        state: result.state,
        client_id: result.clientId,
        expires_at: result.expiresAt,
      })
    } catch (err) {
      const errorResponse = handleError(err)
      const status = errorResponse.error === 'internal_server_error' ? 500 : 400
      return c.json(errorResponse, status)
    }
  })

  verifyApp.delete('/presentation-transaction/:transactionId', async (c) => {
    const transactionId = c.req.param('transactionId')?.trim() ?? ''
    if (transactionId === '') {
      return c.json(
        { error: 'invalid_request', error_description: 'transactionId is required' },
        400
      )
    }
    try {
      const existing = await verifierFlow.getTransaction(transactionId)
      if (existing.state) {
        vpAudTx.consume(existing.state)
      }
      await verifierFlow.deleteTransaction(transactionId)
      return c.json({ ok: true }, 200)
    } catch (err) {
      const errorResponse = handleError(err)
      const status = errorResponse.error === 'internal_server_error' ? 500 : 400
      return c.json(errorResponse, status)
    }
  })

  return verifyApp
}
