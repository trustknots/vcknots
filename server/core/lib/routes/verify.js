import { Hono } from 'hono';
import { VerifierRequestObjectId, initializeVerifierFlow, VerifierAuthorizationResponse, VerifierClientId, ClientIdentifier, PresentationExchange, } from '@trustknots/vcknots/verifier';
import { randomUUID } from 'node:crypto';
import { handleError } from '../utils/error-handler.js';
export const createVerifierRouter = (context, baseUrl) => {
    const verifyApp = new Hono();
    const verifierFlow = initializeVerifierFlow(context);
    const normalizeContentType = (value) => value.split(';')[0]?.trim().toLowerCase() ?? '';
    const parseFormPayload = (form) => {
        const payload = {};
        const presentationSubmission = form.get('presentation_submission');
        if (typeof presentationSubmission === 'string' && presentationSubmission.trim()) {
            try {
                payload.presentation_submission = JSON.parse(presentationSubmission);
            }
            catch {
                return {
                    ok: false,
                    error: {
                        error: 'invalid_request',
                        error_description: 'presentation_submission must be JSON',
                    },
                };
            }
        }
        const vpToken = form.getAll('vp_token').filter((v) => typeof v === 'string');
        payload.vp_token = vpToken.length === 0 ? undefined : vpToken.length === 1 ? vpToken[0] : vpToken;
        const state = form.get('state');
        if (typeof state === 'string') {
            payload.state = state;
        }
        return { ok: true, payload };
    };
    const canHandleClientIdScheme = ['redirect_uri', 'x509_san_dns'];
    function validateClientIdScheme(client_id) {
        if (client_id == null || client_id === '') {
            return 'x509_san_dns:localhost';
        }
        const m = client_id.match(/^([^:]+):(.+)$/);
        const prefix = m?.[1];
        if (!prefix || !canHandleClientIdScheme.includes(prefix)) {
            throw new Error('Invalid client_id format');
        }
        return ClientIdentifier(client_id);
    }
    verifyApp.post('/request', async (c) => {
        try {
            const verifierId = VerifierClientId(baseUrl);
            const body = await c.req.json().catch(() => ({}));
            const credentialId = ('credentialId' in body ? body.credentialId : undefined);
            if (!credentialId) {
                return c.json({
                    error: 'invalid_request',
                    error_description: 'credentialId is required.',
                }, 400);
            }
            const client_id = validateClientIdScheme(body.client_id);
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
            });
            const request = await verifierFlow.createAuthzRequest(verifierId, 'vp_token', client_id, 'direct_post', query, false, {
                response_uri: `${baseUrl}/callback`,
                base_url: baseUrl,
            });
            const encoded = Object.entries(request)
                .map(([key, value]) => {
                const encode = value && typeof value === 'object' ? JSON.stringify(value) : String(value);
                return `${encodeURIComponent(key)}=${encodeURIComponent(encode)}`;
            })
                .join('&');
            return c.text(`openid4vp://authorize?${encoded}`);
        }
        catch (err) {
            return c.json(handleError(err), 400);
        }
    });
    // Receive the vp_token from the request and verify it
    verifyApp.post('/callback', async (c) => {
        try {
            const verifierId = VerifierClientId(baseUrl);
            const contentType = normalizeContentType(c.req.header('content-type') ?? '');
            if (contentType !== 'application/x-www-form-urlencoded') {
                return c.json({
                    error: 'invalid_request',
                    error_description: 'content-type must be application/x-www-form-urlencoded',
                }, 400);
            }
            const formData = await c.req.formData();
            console.log('Form data received:', formData);
            const parsed = parseFormPayload(formData);
            if (!parsed.ok) {
                return c.json(parsed.error, 400);
            }
            // Validate it using the AuthorizationResponse
            const authorizationResponse = VerifierAuthorizationResponse(parsed.payload);
            // Add additional validation as needed
            await verifierFlow.verifyPresentations(verifierId, authorizationResponse);
            return c.json({ redirect_uri: `${baseUrl}/verified` }, 200);
            // return c.json({
            //   message: 'Callback received successfully',
            //   authorization_response: authorizationResponse,
            // })
        }
        catch (err) {
            return c.json(handleError(err), 400);
        }
    });
    verifyApp.post('/callback-kbjwt', async (c) => {
        try {
            const verifierId = VerifierClientId(baseUrl);
            console.log('Form data received:', await c.req.formData());
            const parsed = parseFormPayload(await c.req.formData());
            if (!parsed.ok) {
                return c.json(parsed.error, 400);
            }
            // Validate it using the AuthorizationResponse
            const authorizationResponse = VerifierAuthorizationResponse(parsed.payload);
            const isKbjwt = true;
            // Add additional validation as needed
            await verifierFlow.verifyPresentations(verifierId, authorizationResponse, isKbjwt);
            return c.json({ redirect_uri: `${baseUrl}/verified` }, 200);
            // return c.json({
            //   message: 'Callback received successfully',
            //   authorization_response: authorizationResponse,
            // })
        }
        catch (err) {
            return c.json(handleError(err), 400);
        }
    });
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
    };
    verifyApp.post('/request-object', async (c) => {
        const raw = await c.req.text();
        let parsed = {};
        if (raw.trim()) {
            try {
                parsed = JSON.parse(raw);
            }
            catch (e) {
                parsed = {};
            }
        }
        const input = parsed && typeof parsed === 'object' ? parsed : {};
        const requestObject = {
            query: typeof input.query === 'object' && input.query !== null
                ? input.query
                : {
                    presentation_definition: presentationDefinitionJwtVC,
                },
            state: typeof input.state === 'string' && input.state.trim() !== ''
                ? input.state
                : randomUUID().replaceAll('-', ''),
            base_url: typeof input.base_url === 'string' && input.base_url.trim() !== ''
                ? input.base_url
                : baseUrl,
            is_request_uri: typeof input.is_request_uri === 'boolean' ? input.is_request_uri : true,
            is_transaction_data: typeof input.is_transaction_data === 'boolean' ? input.is_transaction_data : false,
            response_uri: typeof input.response_uri === 'string' && input.response_uri.trim() !== ''
                ? input.response_uri
                : undefined,
            client_id: typeof input.client_id === 'string' && input.client_id.trim() !== ''
                ? validateClientIdScheme(input.client_id)
                : 'x509_san_dns:localhost',
        };
        try {
            const verifierId = VerifierClientId(baseUrl);
            const request = await verifierFlow.createAuthzRequest(verifierId, 'vp_token', requestObject.client_id, 'direct_post', requestObject.query, requestObject.is_request_uri, {
                state: requestObject.state,
                base_url: baseUrl,
                response_uri: requestObject.response_uri ?? `${baseUrl}/callback`,
                request_uri: `${baseUrl}/request.jwt`,
                ...(requestObject.is_transaction_data
                    ? { transaction_data: { type: 'sample_type' } }
                    : {}),
            });
            const encoded = Object.entries(request)
                .map(([key, value]) => {
                const encode = value && typeof value === 'object' ? JSON.stringify(value) : String(value);
                return `${encodeURIComponent(key)}=${encodeURIComponent(encode)}`;
            })
                .join('&');
            return c.text(`openid4vp://authorize?${encoded}`);
        }
        catch (err) {
            return c.json(handleError(err), 400);
        }
    });
    verifyApp.get('/request.jwt/:request-object-Id', async (c) => {
        try {
            const verifierId = VerifierClientId(baseUrl);
            const requestObjectId = VerifierRequestObjectId(c.req.param('request-object-Id'));
            const jar = await verifierFlow.findRequestObject(verifierId, requestObjectId);
            return c.body(jar, 200, {
                'Content-Type': 'application/oauth-authz-req+jwt',
            });
        }
        catch (err) {
            return c.json(handleError(err), 400);
        }
    });
    verifyApp.get("/verified", async (c) => {
        console.log("Verified received from get request");
        return c.json({ message: "DONE!!" }, 200);
    });
    return verifyApp;
};
//# sourceMappingURL=verify.js.map