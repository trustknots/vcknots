import base64url from 'base64url'
import { importJWK, jwtVerify } from 'jose'
import {
  AuthorizationServerIssuer,
  AuthorizationServerMetadata,
} from './authorization-server.types'
import { AuthzOAuthClient } from './authz-oauth-client.types'
import { AuthzOAuthPolicy, type AuthzClientPolicy, type DPoPMode } from './authz-oauth-policy.types'
import { calculateAccessTokenHash } from './dpop-proof'
import type { DPoPProofVerifyContext } from './dpop-proof.types'
import { err } from './errors/vcknots.error'
import { GrantType, TokenRequest } from './token-request.types'
import { VcknotsContext } from './vcknots.context'
import { JwtPayload } from './jwt.types'
import { Nonce } from './nonce.types'

type AuthzKeyAlg = string
type OAuthClientAuthMethod = string

export { AuthzOAuthClient, AuthzOAuthClients } from './authz-oauth-client.types'
export { AuthzOAuthPolicy } from './authz-oauth-policy.types'
export type { AuthzClientPolicy, DPoPMode } from './authz-oauth-policy.types'

export type AuthzOAuthPolicyClientKind = 'anonymous_client' | 'default_client'

export type OAuthClientConfig = AuthzOAuthClient

const CLIENT_ASSERTION_TYPE_JWT_BEARER = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
const DEFAULT_DPOP_MODE: DPoPMode = 'off'
const MIN_CLIENT_ASSERTION_JTI_TTL_MS = 1
const CLIENT_ASSERTION_CLOCK_TOLERANCE_SECONDS = 10

export type TokenRequestPolicyClientResolution =
  | {
      ok: true
      clientKind: AuthzOAuthPolicyClientKind
      dpopMode: DPoPMode
      clientId?: string
      clientPolicy?: AuthzClientPolicy
    }
  | {
      ok: false
      error: 'invalid_client'
      error_description: string
      clientId?: string
      log?: Record<string, unknown>
    }

export type TokenRequestPolicyClientContextResolution =
  | {
      ok: true
      clientKind: AuthzOAuthPolicyClientKind
      clientId?: string
      clientPolicy?: AuthzClientPolicy
    }
  | {
      ok: false
      error: 'invalid_client'
      error_description: string
      clientId?: string
      log?: Record<string, unknown>
    }

/** Returns true only for non-empty string form values. */
const hasValue = (value: unknown): boolean => typeof value === 'string' && value.trim().length > 0

/** Normalizes optional string form values; blank values are treated as missing. */
const getStringValue = (value: unknown): string | null =>
  typeof value === 'string' && value.trim().length > 0 ? value.trim() : null

/** Decodes a base64url-encoded JWT part as JSON. */
const decodeBase64UrlJson = (value: string): unknown => JSON.parse(base64url.decode(value))

/**
 * Parses a compact JWT without verifying it.
 *
 * This is used only for early client identification and registration lookup; cryptographic
 * verification is still performed later with the selected registered client JWK.
 */
const parseCompactJwt = (
  jwt: string
): { header: Record<string, unknown>; payload: JwtPayload } | null => {
  const parts = jwt.split('.')
  if (parts.length !== 3) return null

  const [headerPart, payloadPart, signaturePart] = parts
  if (!headerPart || !payloadPart || !signaturePart) return null

  try {
    const header = decodeBase64UrlJson(headerPart)
    const payload = decodeBase64UrlJson(payloadPart)
    if (!header || typeof header !== 'object' || !payload || typeof payload !== 'object') {
      return null
    }
    return {
      header: header as Record<string, unknown>,
      payload: payload as JwtPayload,
    }
  } catch {
    return null
  }
}

/**
 * Parses `client_assertion` when it is a compact JWT: returns a client id from `iss` or `sub`
 * when they agree (or only one is present). Invalid JWT shape or conflicting `iss`/`sub` yield `null`.
 */
const extractClientIdFromClientAssertion = (clientAssertion: unknown): string | null => {
  const assertion = getStringValue(clientAssertion)
  if (!assertion) return null

  const [, payload] = assertion.split('.')
  if (!payload) return null

  try {
    const claims = decodeBase64UrlJson(payload)
    if (!claims || typeof claims !== 'object') return null
    const { iss, sub } = claims as { iss?: unknown; sub?: unknown }
    const issuerClientId = getStringValue(iss)
    const subjectClientId = getStringValue(sub)
    // RFC 7523-style client auth JWT usually uses iss == sub as client_id; reject ambiguity.
    if (issuerClientId && subjectClientId && issuerClientId !== subjectClientId) {
      return null
    }
    return issuerClientId ?? subjectClientId
  } catch {
    return null
  }
}

/**
 * Token request client identifier resolution order:
 * 1. Use the request body `client_id` when present.
 * 2. If `client_id` is omitted, derive it from the `client_assertion` JWT `iss` / `sub`.
 * 3. If neither source yields a client id, return `null` so the caller can apply
 *    anonymous client policy.
 *
 * @param requestData - OAuth token request parameters (e.g. `application/x-www-form-urlencoded`).
 * @returns Trimmed client id, or `null` for an anonymous-style request with no derivable id.
 */
export const getTokenRequestClientId = (requestData: Record<string, unknown>): string | null =>
  typeof requestData.client_id === 'string' && requestData.client_id.trim().length > 0
    ? requestData.client_id.trim()
    : extractClientIdFromClientAssertion(requestData.client_assertion)

/** True when the request carries a JWT bearer client assertion suitable for `private_key_jwt`. */
const hasPrivateKeyJwtAssertion = (requestData: Record<string, unknown>): boolean =>
  getStringValue(requestData.client_assertion_type) === CLIENT_ASSERTION_TYPE_JWT_BEARER &&
  hasValue(requestData.client_assertion)

/** User-facing OAuth error_description when `private_key_jwt` prerequisites are missing. */
const missingPrivateKeyJwtAssertionDescription = (requestData: Record<string, unknown>): string => {
  if (getStringValue(requestData.client_assertion_type) !== CLIENT_ASSERTION_TYPE_JWT_BEARER) {
    return 'client_assertion_type must be urn:ietf:params:oauth:client-assertion-type:jwt-bearer for private_key_jwt client authentication.'
  }
  return 'client_assertion is required for private_key_jwt client authentication.'
}

/** Registered token endpoint authentication method, defaulting to public/none. */
const getTokenEndpointAuthMethod = (client: OAuthClientConfig): OAuthClientAuthMethod =>
  client.token_endpoint_auth_method ?? 'none'

/** True only for Pre-Authorized Code token requests; other grant types are not anonymous-access gated here. */
const isPreAuthorizedCodeTokenRequest = (requestData: Record<string, unknown>): boolean =>
  getStringValue(requestData.grant_type) === GrantType.PreAuthorizedCode

/**
 * Expected `aud` values for private_key_jwt.
 *
 * Prefer explicit client registration, then AS metadata token endpoint, with issuer as a fallback
 * for sample metadata that does not carry a token endpoint.
 */
const getExpectedClientAssertionAudiences = (
  client: OAuthClientConfig,
  metadata: AuthorizationServerMetadata | null,
  authz: AuthorizationServerIssuer
): string[] => {
  const configuredAudience = getStringValue(client.client_assertion_audience)
  if (configuredAudience) return [configuredAudience]
  // private_key_jwt is presented to the token endpoint. The issuer fallback keeps
  // existing sample/test metadata usable when token_endpoint is not registered.
  return metadata?.token_endpoint ? [metadata.token_endpoint, authz] : [authz]
}

/** Returns a clearer OAuth error when the assertion audience mismatches registration. */
const clientAssertionVerificationDescription = (
  client: OAuthClientConfig,
  expectedAudiences: string[],
  cause: string
): string => {
  const configuredAudience = getStringValue(client.client_assertion_audience)
  if (!cause.includes('"aud"') && !cause.toLowerCase().includes('audience')) {
    return 'client_assertion verification failed.'
  }
  if (configuredAudience) {
    return `client_assertion aud claim does not match registered client_assertion_audience setting (${configuredAudience}).`
  }
  return `client_assertion aud claim does not match expected audience (${expectedAudiences.join(', ')}).`
}

/**
 * Selects the registered public JWK used to verify `client_assertion`.
 *
 * When `kid` is present, it must match a registered key. Without `kid`, selection is allowed only
 * when the client has exactly one registered key.
 */
const selectClientAssertionJwk = (
  client: OAuthClientConfig,
  protectedHeader: Record<string, unknown>
): Record<string, unknown> | null => {
  const keys = client.jwks?.keys
  if (!keys || keys.length === 0) return null

  const kid = getStringValue(protectedHeader.kid)
  if (kid) {
    return keys.find((key) => getStringValue(key.kid) === kid) ?? null
  }

  return keys.length === 1 ? keys[0] : null
}

/**
 * Verifies OAuth `private_key_jwt` client authentication for the token endpoint.
 *
 * This stays in AuthzFlow rather than server routes because client registry lookup,
 * assertion validation, and OAuth policy resolution are library concerns.
 */
const verifyPrivateKeyJwtClientAuthentication = async (
  authz: AuthorizationServerIssuer,
  metadata: AuthorizationServerMetadata | null,
  requestData: Record<string, unknown>,
  client: OAuthClientConfig
): Promise<PrivateKeyJwtClientAuthVerification> => {
  // private_key_jwt requires both the JWT bearer assertion type and the assertion JWT itself.
  if (!hasPrivateKeyJwtAssertion(requestData)) {
    return {
      ok: false,
      error_description: missingPrivateKeyJwtAssertionDescription(requestData),
      log: {
        clientId: client.client_id,
        tokenEndpointAuthMethod: getTokenEndpointAuthMethod(client),
        hasClientAssertionType: hasValue(requestData.client_assertion_type),
        hasClientAssertion: hasValue(requestData.client_assertion),
      },
    }
  }

  // Use a normalized string value before parsing so blank form fields are rejected.
  const clientAssertion = getStringValue(requestData.client_assertion)
  if (!clientAssertion) {
    return {
      ok: false,
      error_description: 'client_assertion is required for private_key_jwt client authentication.',
    }
  }

  // The client assertion must be a compact JWT: <protected header>.<payload>.<signature>.
  const assertion = parseCompactJwt(clientAssertion)
  if (!assertion) {
    return {
      ok: false,
      error_description: 'client_assertion must be a compact JWT.',
      log: { clientId: client.client_id },
    }
  }

  const assertionIssuer = getStringValue(assertion.payload.iss)
  const assertionSubject = getStringValue(assertion.payload.sub)
  // For private_key_jwt client authentication, iss and sub identify the registered client.
  if (assertionIssuer !== client.client_id || assertionSubject !== client.client_id) {
    return {
      ok: false,
      error_description: 'client_assertion iss and sub must match the registered client_id.',
      log: {
        clientId: client.client_id,
        assertionIssuer,
        assertionSubject,
      },
    }
  }
  // exp is required so jwtVerify can reject expired assertions instead of accepting long-lived JWTs.
  if (typeof assertion.payload.exp !== 'number') {
    return {
      ok: false,
      error_description: 'client_assertion exp claim is required.',
      log: { clientId: client.client_id },
    }
  }
  // iat is required here so the AS can enforce strict client assertion freshness.
  // FAPI 2.0 Security Profile Note 3 requires accepting up to 10 seconds of
  // future clock skew, while rejecting timestamps more than 60 seconds in the
  // future. This implementation uses the stricter 10-second tolerance, so
  // assertions beyond that window are rejected before downstream policy checks.
  const now = Math.floor(Date.now() / 1000)
  if (typeof assertion.payload.iat !== 'number') {
    return {
      ok: false,
      error_description: 'client_assertion iat claim is required.',
      log: { clientId: client.client_id },
    }
  }
  if (assertion.payload.iat > now + CLIENT_ASSERTION_CLOCK_TOLERANCE_SECONDS) {
    return {
      ok: false,
      error_description: 'client_assertion iat claim is too far in the future.',
      log: {
        clientId: client.client_id,
        iat: assertion.payload.iat,
        now,
        clockToleranceSeconds: CLIENT_ASSERTION_CLOCK_TOLERANCE_SECONDS,
      },
    }
  }
  // nbf is optional, but if present it must follow the same FAPI Note 3
  // future clock-skew window used for iat.
  if (
    typeof assertion.payload.nbf === 'number' &&
    assertion.payload.nbf > now + CLIENT_ASSERTION_CLOCK_TOLERANCE_SECONDS
  ) {
    return {
      ok: false,
      error_description: 'client_assertion nbf claim is too far in the future.',
      log: {
        clientId: client.client_id,
        nbf: assertion.payload.nbf,
        now,
        clockToleranceSeconds: CLIENT_ASSERTION_CLOCK_TOLERANCE_SECONDS,
      },
    }
  }
  // jti is required for private_key_jwt assertions; the flow stores it after signature validation.
  const assertionJti = getStringValue(assertion.payload.jti)
  if (!assertionJti) {
    return {
      ok: false,
      error_description: 'client_assertion jti claim is required.',
      log: { clientId: client.client_id },
    }
  }

  const alg = getStringValue(assertion.header.alg)
  const expectedAlg = getStringValue(client.token_endpoint_auth_signing_alg)
  const supportedAuthMethods = metadata?.token_endpoint_auth_methods_supported
  const supportedAlgs = metadata?.token_endpoint_auth_signing_alg_values_supported
  // Reject unsigned JWTs and symmetric MAC algorithms; client authentication must use registered public keys.
  if (!alg || alg.toLowerCase() === 'none' || /^hs/i.test(alg)) {
    return {
      ok: false,
      error_description: 'client_assertion alg must be an asymmetric signing algorithm.',
      log: { clientId: client.client_id, alg },
    }
  }
  // private_key_jwt is only accepted when the Authorization Server metadata advertises it.
  if (!supportedAuthMethods?.includes('private_key_jwt')) {
    return {
      ok: false,
      error_description:
        'authorization server metadata must include private_key_jwt in token_endpoint_auth_methods_supported for private_key_jwt client authentication.',
      log: { clientId: client.client_id, supportedAuthMethods },
    }
  }
  // private_key_jwt requires the Authorization Server metadata to declare accepted assertion algs.
  if (!supportedAlgs?.length) {
    return {
      ok: false,
      error_description:
        'authorization server metadata must include token_endpoint_auth_signing_alg_values_supported for private_key_jwt client authentication.',
      log: { clientId: client.client_id },
    }
  }
  // The assertion header alg must be one of the algorithms advertised by AS metadata.
  if (!supportedAlgs.includes(alg)) {
    return {
      ok: false,
      error_description:
        'client_assertion alg is not supported by the authorization server metadata.',
      log: { clientId: client.client_id, alg, supportedAlgs },
    }
  }
  // If the client registration pins an algorithm, the assertion header must match it.
  if (expectedAlg && alg !== expectedAlg) {
    return {
      ok: false,
      error_description: 'client_assertion alg does not match the registered client algorithm.',
      log: { clientId: client.client_id, alg, expectedAlg },
    }
  }

  // Select the registered public JWK by kid. Without kid, only a single registered key is unambiguous.
  const jwk = selectClientAssertionJwk(client, assertion.header)
  if (!jwk) {
    return {
      ok: false,
      error_description: 'Registered OAuth client public key was not found.',
      log: {
        clientId: client.client_id,
        kid: getStringValue(assertion.header.kid),
        jwksKeyCount: client.jwks?.keys.length ?? 0,
      },
    }
  }

  // JWK alg policy: the assertion header alg is authoritative for importJWK/jwtVerify.
  // When the registered public key includes alg, it must match the header; otherwise reject
  // with a deterministic error instead of relying on importJWK's internal failure.
  const jwkAlg = getStringValue(jwk.alg)
  if (jwkAlg && jwkAlg !== alg) {
    return {
      ok: false,
      error_description:
        'Registered client public key alg does not match client_assertion header alg.',
      log: { clientId: client.client_id, alg, jwkAlg },
    }
  }

  try {
    const key = await importJWK(jwk, alg)
    const expectedAudiences = getExpectedClientAssertionAudiences(client, metadata, authz)
    // `jwtVerify` checks signature and registered JWT claims here:
    // iss/sub must be the client_id, aud must target this token endpoint, and exp must be valid.
    await jwtVerify(clientAssertion, key, {
      issuer: client.client_id,
      subject: client.client_id,
      audience: expectedAudiences,
      clockTolerance: CLIENT_ASSERTION_CLOCK_TOLERANCE_SECONDS,
    })
    return { ok: true, jti: assertionJti, exp: assertion.payload.exp }
  } catch (error) {
    const cause = error instanceof Error ? error.message : String(error)
    const expectedAudiences = getExpectedClientAssertionAudiences(client, metadata, authz)
    return {
      ok: false,
      error_description: clientAssertionVerificationDescription(client, expectedAudiences, cause),
      log: {
        clientId: client.client_id,
        expectedAudiences,
        cause,
      },
    }
  }
}

/**
 * Coarse issuer OAuth policy bucket for a token request: `default_client` vs `anonymous_client`.
 * Does not validate registration or auth method; use {@link resolveTokenRequestPolicyClientContext} for that.
 */
export const resolveTokenRequestPolicyClient = (
  requestData: Record<string, unknown>
): AuthzOAuthPolicyClientKind =>
  hasValue(requestData.client_id) || hasValue(requestData.client_assertion)
    ? 'default_client'
    : 'anonymous_client'

/**
 * Resolves OAuth client context for a token endpoint request: anonymous vs registered client,
 * and whether the request satisfies the registered client's authentication method.
 *
 * Callers must pass the result of a registry lookup: when `getTokenRequestClientId` returns an
 * id, `client` should be the stored {@link OAuthClientConfig} for that issuer/id, or `null` if
 * unknown. Outputs feed DPoP / sender-constraint policy resolution (`clientPolicy` overrides
 * issuer defaults when present).
 *
 * @param requestData - Raw token request body (e.g. form fields); `client_id` and/or
 *   `client_assertion` drive client identification.
 * @param client - Registered client for `getTokenRequestClientId(requestData)`, or `null` if none.
 * @returns Success with `clientKind` and optional per-client `clientPolicy`, or `invalid_client`.
 */
export const resolveTokenRequestPolicyClientContext = (
  requestData: Record<string, unknown>,
  client: OAuthClientConfig | null
): TokenRequestPolicyClientContextResolution => {
  const clientId = getTokenRequestClientId(requestData)

  // No resolvable client id: anonymous flow, unless an assertion was sent without iss/sub.
  if (!clientId) {
    if (hasValue(requestData.client_assertion)) {
      return {
        ok: false,
        error: 'invalid_client',
        error_description: 'client_assertion must contain iss or sub client identifier.',
        log: {
          hasClientAssertionType: hasValue(requestData.client_assertion_type),
          hasClientAssertion: true,
        },
      }
    }
    return { ok: true, clientKind: 'anonymous_client' }
  }

  // Identified client must exist in the authorization server's registry.
  if (!client) {
    return {
      ok: false,
      error: 'invalid_client',
      error_description: 'Registered OAuth client was not found.',
      clientId,
    }
  }

  const tokenEndpointAuthMethod = getTokenEndpointAuthMethod(client)

  // Enforce private_key_jwt material when the registered client requires it.
  if (tokenEndpointAuthMethod === 'private_key_jwt') {
    if (!hasPrivateKeyJwtAssertion(requestData)) {
      return {
        ok: false,
        error: 'invalid_client',
        error_description: missingPrivateKeyJwtAssertionDescription(requestData),
        clientId,
        log: {
          clientId,
          tokenEndpointAuthMethod,
          hasClientAssertionType: hasValue(requestData.client_assertion_type),
          hasClientAssertion: hasValue(requestData.client_assertion),
        },
      }
    }
  } else if (tokenEndpointAuthMethod !== 'none') {
    // Other token_endpoint_auth_method values are rejected until implemented.
    return {
      ok: false,
      error: 'invalid_client',
      error_description: `${tokenEndpointAuthMethod} client authentication is not implemented yet.`,
      clientId,
      log: {
        clientId,
        tokenEndpointAuthMethod,
      },
    }
  }

  // Registered client: optional sender-constraint policy slice for downstream DPoP resolution.
  return {
    ok: true,
    clientKind: 'default_client',
    clientId,
    clientPolicy: client.senderConstrainedAccessToken
      ? { senderConstrainedAccessToken: client.senderConstrainedAccessToken }
      : undefined,
  }
}

/**
 * Computes DPoP usage mode (`off` / `optional` / `required`) from issuer policy and optional
 * per-client overrides. Per-client {@link AuthzClientPolicy} wins over `default_client` /
 * `anonymous_client` slices in stored {@link AuthzOAuthPolicy}.
 *
 * @param authzFlow - Flow with `findAuthzOAuthPolicy` (standalone helper; prefers this over store access).
 * @param clientKind - Policy bucket when no per-client `senderConstrainedAccessToken` override exists.
 * @param clientPolicy - Optional slice from a registered client (e.g. token endpoint path).
 */
export const resolveAuthzPolicyDpopMode = async (
  authzFlow: Pick<AuthzFlow, 'findAuthzOAuthPolicy'>,
  authz: AuthorizationServerIssuer,
  clientKind: AuthzOAuthPolicyClientKind,
  clientPolicy?: AuthzClientPolicy
): Promise<DPoPMode> => {
  const policy = await authzFlow.findAuthzOAuthPolicy(authz)
  const senderConstraint =
    clientPolicy?.senderConstrainedAccessToken ?? policy?.[clientKind]?.senderConstrainedAccessToken

  // No sender constraint → treat as bearer; DPoP mode off.
  if (!senderConstraint) return DEFAULT_DPOP_MODE
  // mTLS or explicit none: not DPoP-bound in this layer.
  if (senderConstraint.method === 'none' || senderConstraint.method === 'mtls') {
    return DEFAULT_DPOP_MODE
  }

  return senderConstraint.dpop?.mode ?? DEFAULT_DPOP_MODE
}

type DPoPProofContext = {
  proofJwt: string
  htm: string
  htu: string
  // Defaults to false. Set true when the endpoint requires a DPoP nonce challenge.
  nonceRequired?: boolean
}

type TokenRequestOptions = {
  [GrantType.AuthorizationCode]: {
    //TODO: Implement options for authorization code flow
    alg?: AuthzKeyAlg
    clientId?: AuthzOAuthClient['client_id']
    dpopProof?: DPoPProofContext
  }
  [GrantType.PreAuthorizedCode]: {
    ttlSec?: number
    alg?: AuthzKeyAlg
    clientId?: AuthzOAuthClient['client_id']
    dpopProof?: DPoPProofContext
  }
}

type AnyTokenRequestOptions =
  | TokenRequestOptions[GrantType.AuthorizationCode]
  | TokenRequestOptions[GrantType.PreAuthorizedCode]

type PrivateKeyJwtClientAuthVerification =
  | { ok: true; jti: string; exp: number }
  | {
      ok: false
      error_description: string
      log?: Record<string, unknown>
    }

type AccessTokenVerifyOptions = { alg?: AuthzKeyAlg }

type DPoPBoundAccessTokenVerifyOptions = AccessTokenVerifyOptions & {
  dpopProof: DPoPProofContext
}

/**
 * Authorization-server capabilities: AS metadata, OAuth client/policy stores, DPoP-aware token
 * endpoint helpers, access token creation (pre-authorized code grant), and access token verification.
 */
export type AuthzFlow = {
  findAuthzServerMetadata(
    issuer: AuthorizationServerIssuer
  ): Promise<AuthorizationServerMetadata | null>
  createAuthzServerMetadata(
    metadata: AuthorizationServerMetadata,
    options?: { alg?: AuthzKeyAlg }
  ): Promise<void>
  findAuthzOAuthPolicy(issuer: AuthorizationServerIssuer): Promise<AuthzOAuthPolicy | null>
  createAuthzOAuthPolicy(issuer: AuthorizationServerIssuer, policy: AuthzOAuthPolicy): Promise<void>
  findAuthzOAuthClient(
    issuer: AuthorizationServerIssuer,
    clientId: AuthzOAuthClient['client_id']
  ): Promise<AuthzOAuthClient | null>
  createAuthzOAuthClient(issuer: AuthorizationServerIssuer, client: AuthzOAuthClient): Promise<void>
  resolveAuthzPolicyDpopMode(
    authz: AuthorizationServerIssuer,
    clientKind: AuthzOAuthPolicyClientKind,
    clientPolicy?: AuthzClientPolicy
  ): Promise<DPoPMode>
  resolveTokenRequestClientPolicy(
    authz: AuthorizationServerIssuer,
    requestData: Record<string, unknown>
  ): Promise<TokenRequestPolicyClientResolution>
  createDpopNonceChallenge(ttlMs?: number): Promise<string>
  createAccessToken(
    authz: AuthorizationServerIssuer,
    tokenRequest: TokenRequest,
    options?: AnyTokenRequestOptions
    // biome-ignore lint/complexity/noBannedTypes: <explanation>
  ): Promise<Object>
  verifyAccessToken(
    authz: AuthorizationServerIssuer,
    accessToken: string,
    options?: AccessTokenVerifyOptions
  ): Promise<boolean>
  /** Bearer access token: decode, issuer check, signature verification; returns JWT payload. */
  verifyAccessTokenPayload(
    authz: AuthorizationServerIssuer,
    accessToken: string,
    options?: AccessTokenVerifyOptions
  ): Promise<JwtPayload>
  /** DPoP access token: bearer checks plus proof, optional nonce, `cnf.jkt` match, and jti replay guard. */
  verifyDpopBoundAccessToken(
    authz: AuthorizationServerIssuer,
    accessToken: string,
    options: DPoPBoundAccessTokenVerifyOptions
  ): Promise<JwtPayload>
}

/**
 * Builds an {@link AuthzFlow} using providers registered on {@link VcknotsContext}
 * (`authz-server-metadata-store-provider`, `authz-oauth-policy-store-provider`, etc.).
 */
export const initializeAuthzFlow = (context: VcknotsContext): AuthzFlow => {
  const authz$ = context.providers.get('authz-server-metadata-store-provider')
  const authzOAuthPolicy$ = context.providers.get('authz-oauth-policy-store-provider')
  const authzOAuthClient$ = context.providers.get('authz-oauth-client-store-provider')
  const codeStore$ = context.providers.get('pre-authorized-code-store-provider')
  const accessToken$ = context.providers.get('access-token-provider')
  const authzKey$ = context.providers.get('authz-signature-key-store-provider')
  const dpopProof$ = context.providers.get('dpop-proof-provider')
  const dpopProofJtiStore$ = context.providers.get('dpop-proof-jti-store-provider')
  const oauthClientAssertionJtiStore$ = context.providers.get(
    'oauth-client-assertion-jti-store-provider'
  )
  const issuanceContextStore$ = context.providers.get('issuance-context-store-provider')

  /**
   * Verifies a bearer-style access token JWT: shape, issuer matches `authz`, signature with stored AS key.
   * @throws Vcknots errors for malformed JWT, wrong issuer, missing key, or failed `jwtVerify`.
   */
  const verifyAccessTokenPayload = async (
    authz: AuthorizationServerIssuer,
    accessToken: string,
    options?: AccessTokenVerifyOptions
  ): Promise<JwtPayload> => {
    const [jwtHeader, jwtPayload, jwtSignature] = accessToken.split('.')
    if (!jwtHeader || !jwtPayload || !jwtSignature) {
      throw err('invalid_access_token', {
        message: 'Access token is not a valid JWT.',
      })
    }

    let decodedHeader: { alg?: AuthzKeyAlg }
    let decodedPayload: JwtPayload
    try {
      decodedHeader = JSON.parse(base64url.decode(jwtHeader))
      decodedPayload = JSON.parse(base64url.decode(jwtPayload))
    } catch (error) {
      throw err('invalid_access_token', {
        message:
          error instanceof Error
            ? `Access token is not a valid JWT. ${error.message}`
            : 'Access token is not a valid JWT.',
      })
    }

    // Reject tokens issued for a different authorization server than the caller expects.
    const authzIssuer = AuthorizationServerIssuer(decodedPayload.iss)
    if (authzIssuer !== authz) {
      throw err('invalid_access_token', {
        message: `Access token issuer ${authzIssuer} does not match the expected issuer ${authz}.`,
      })
    }
    const keyAlg = decodedHeader.alg ?? options?.alg ?? 'ES256'
    const publicKey = await authzKey$.fetch(authzIssuer, keyAlg)
    if (!publicKey) {
      throw err('authz_issuer_key_not_found', {
        message: `Authorization server key for ${authzIssuer} not found.`,
      })
    }

    try {
      await jwtVerify(accessToken, publicKey, {
        issuer: decodedPayload.iss,
      })
    } catch {
      throw err('invalid_access_token', {
        message: 'Access token verification failed.',
      })
    }
    return decodedPayload
  }

  /** Extracts DPoP-demonstration key thumbprint from RFC 7800 `cnf.jkt` if present. */
  const getCnfJkt = (payload: JwtPayload): string | undefined => {
    const cnf = payload.cnf
    if (cnf === null || typeof cnf !== 'object' || Array.isArray(cnf)) {
      return undefined
    }
    const jkt = (cnf as { jkt?: unknown }).jkt
    return typeof jkt === 'string' && jkt.trim().length > 0 ? jkt : undefined
  }

  /**
   * DPoP-bound access token path: after JWT verification, checks proof `ath`, optional nonce,
   * matches proof JWK thumbprint to `cnf.jkt`, then enforces single-use DPoP `jti` per key.
   */
  const verifyDpopBoundAccessToken = async (
    authz: AuthorizationServerIssuer,
    accessToken: string,
    options: DPoPBoundAccessTokenVerifyOptions
  ): Promise<JwtPayload> => {
    const nonceRequired = options.dpopProof.nonceRequired ?? false

    // Validate in dependency order: access token, DPoP proof, optional nonce,
    // cnf.jkt binding, then jti replay. This avoids consuming nonce/jti before
    // the presented token and proof are structurally valid.
    const payload = await verifyAccessTokenPayload(authz, accessToken, options)
    const accessTokenJkt = getCnfJkt(payload)
    if (!accessTokenJkt) {
      throw err('invalid_access_token', {
        message: 'DPoP-bound access token must contain cnf.jkt.',
      })
    }

    const verifiedDpopProof = await dpopProof$.verifyProof(options.dpopProof.proofJwt, {
      htm: options.dpopProof.htm,
      htu: options.dpopProof.htu,
      // Credential endpoint DPoP proofs must bind to the presented access token via `ath`.
      accessToken,
    } satisfies DPoPProofVerifyContext)

    if (nonceRequired) {
      const nonceStore$ = context.providers.get('nonce-store-provider')
      if (!verifiedDpopProof.nonce) {
        throw err('use_dpop_nonce', {
          message: 'Credential issuer requires nonce in DPoP proof.',
        })
      }
      const consumed = await nonceStore$.consume(Nonce({ nonce: verifiedDpopProof.nonce }))
      if (!consumed) {
        throw err('use_dpop_nonce', {
          message: 'Credential issuer requires nonce in DPoP proof.',
        })
      }
    }

    // Bind the access token to the DPoP proof key via cnf.jkt.
    if (verifiedDpopProof.jwkThumbprint !== accessTokenJkt) {
      throw err('invalid_dpop_proof', {
        message: 'DPoP proof public key does not match access token cnf.jkt.',
      })
    }

    // Reject replayed DPoP proofs by storing jti per proof public key thumbprint.
    // The cache TTL follows the proof validity window, so a jti is retained
    // while the corresponding proof could still pass iat/maxTokenAge validation.
    const isNewJti = await dpopProofJtiStore$.saveIfAbsent(
      verifiedDpopProof.jwkThumbprint,
      verifiedDpopProof.jti,
      { ttlMs: dpopProof$.proofJtiTtlMs }
    )
    if (!isNewJti) {
      throw err('invalid_dpop_proof', {
        message: 'DPoP proof JWT jti has already been used.',
      })
    }

    return payload
  }

  /**
   * Same DPoP mode resolution as {@link resolveAuthzPolicyDpopMode}, but reads policy via the
   * initialized `authz-oauth-policy-store-provider` (no `AuthzFlow` indirection).
   */
  const resolveAuthzPolicyDpopModeForIssuer = async (
    authz: AuthorizationServerIssuer,
    clientKind: AuthzOAuthPolicyClientKind,
    clientPolicy?: AuthzClientPolicy
  ): Promise<DPoPMode> => {
    const policy = await authzOAuthPolicy$.fetch(authz)
    const senderConstraint =
      clientPolicy?.senderConstrainedAccessToken ??
      policy?.[clientKind]?.senderConstrainedAccessToken

    // Align with exported resolveAuthzPolicyDpopMode: no constraint or non-DPoP methods → off.
    if (!senderConstraint) return DEFAULT_DPOP_MODE
    if (senderConstraint.method === 'none' || senderConstraint.method === 'mtls') {
      return DEFAULT_DPOP_MODE
    }

    return senderConstraint.dpop?.mode ?? DEFAULT_DPOP_MODE
  }

  return {
    /** Loads RFC 8414-style authorization server metadata for `issuer`, if stored. */
    async findAuthzServerMetadata(issuer) {
      return await authz$.fetch(issuer)
    },
    /**
     * Registers new AS metadata and provisions a signing key for JWT access tokens / responses.
     * @throws When metadata for `metadata.issuer` already exists.
     */
    async createAuthzServerMetadata(metadata, options) {
      const privateKeyAlg = options?.alg ?? 'ES256'
      const current = await authz$.fetch(metadata.issuer)
      if (current) {
        throw err('duplicate_authz_server', {
          message: `issuer ${metadata.issuer} is already registered.`,
        })
      }
      // Persist key material before metadata so token issuance can resolve keys by issuer.
      await authzKey$.save(metadata.issuer, privateKeyAlg)
      await authz$.save(metadata)
    },
    /** Reads issuer-level OAuth policy (`default_client` / `anonymous_client` sender constraints). */
    async findAuthzOAuthPolicy(issuer) {
      return await authzOAuthPolicy$.fetch(issuer)
    },
    /** Persists or replaces {@link AuthzOAuthPolicy} for the authorization server `issuer`. */
    async createAuthzOAuthPolicy(issuer, policy) {
      await authzOAuthPolicy$.save(issuer, policy)
    },
    /** Looks up a registered OAuth client by `client_id` under this authorization server `issuer`. */
    async findAuthzOAuthClient(issuer, clientId) {
      return await authzOAuthClient$.fetch(issuer, clientId)
    },
    /** Registers or updates an {@link AuthzOAuthClient} for `issuer`. */
    async createAuthzOAuthClient(issuer, client) {
      await authzOAuthClient$.save(issuer, client)
    },
    /**
     * Computes effective DPoP mode for this flow's policy store and optional per-client override.
     * Thin wrapper around {@link resolveAuthzPolicyDpopModeForIssuer}.
     */
    async resolveAuthzPolicyDpopMode(authz, clientKind, clientPolicy) {
      return await resolveAuthzPolicyDpopModeForIssuer(authz, clientKind, clientPolicy)
    },
    /**
     * End-to-end token-request policy: registry lookup, client auth validation, then `dpopMode`.
     * On failure returns `invalid_client` without evaluating DPoP mode.
     */
    async resolveTokenRequestClientPolicy(authz, requestData) {
      const clientId = getTokenRequestClientId(requestData)
      const oauthClient = clientId ? await authzOAuthClient$.fetch(authz, clientId) : null
      const clientResolution = resolveTokenRequestPolicyClientContext(requestData, oauthClient)
      if (!clientResolution.ok) {
        return clientResolution
      }
      const needsMetadata =
        (clientResolution.clientKind === 'anonymous_client' &&
          isPreAuthorizedCodeTokenRequest(requestData)) ||
        (oauthClient && getTokenEndpointAuthMethod(oauthClient) === 'private_key_jwt')
      const metadata = needsMetadata ? await authz$.fetch(authz) : null
      if (
        clientResolution.clientKind === 'anonymous_client' &&
        isPreAuthorizedCodeTokenRequest(requestData) &&
        metadata?.['pre-authorized_grant_anonymous_access_supported'] !== true
      ) {
        return {
          ok: false,
          error: 'invalid_client',
          error_description:
            'anonymous pre-authorized code token requests are not supported by this authorization server.',
          log: {
            grantType: getStringValue(requestData.grant_type),
            preAuthorizedGrantAnonymousAccessSupported:
              metadata?.['pre-authorized_grant_anonymous_access_supported'],
          },
        }
      }
      if (oauthClient && getTokenEndpointAuthMethod(oauthClient) === 'private_key_jwt') {
        const verification = await verifyPrivateKeyJwtClientAuthentication(
          authz,
          metadata,
          requestData,
          oauthClient
        )
        if (!verification.ok) {
          return {
            ok: false,
            error: 'invalid_client',
            error_description: verification.error_description,
            clientId: oauthClient.client_id,
            log: verification.log,
          }
        }
        // Store private_key_jwt client_assertion jti only after the assertion signature and
        // registered claims were verified. The TTL follows assertion exp so replay protection
        // lasts for the whole assertion lifetime without retaining entries longer than needed.
        const ttlMs = verification.exp * 1000 - Date.now()
        // jwtVerify may accept exp within clock tolerance while ttlMs is already <= 0; do not
        // treat that as JTI reuse.
        if (ttlMs < MIN_CLIENT_ASSERTION_JTI_TTL_MS) {
          return {
            ok: false,
            error: 'invalid_client',
            error_description: 'client_assertion has expired.',
            clientId: oauthClient.client_id,
            log: {
              clientId: oauthClient.client_id,
              jti: verification.jti,
              exp: verification.exp,
              ttlMs,
            },
          }
        }
        const isNewJti = await oauthClientAssertionJtiStore$.saveIfAbsent(
          oauthClient.client_id,
          verification.jti,
          { ttlMs }
        )
        if (!isNewJti) {
          return {
            ok: false,
            error: 'invalid_client',
            error_description: 'client_assertion jti has already been used.',
            clientId: oauthClient.client_id,
            log: {
              clientId: oauthClient.client_id,
              jti: verification.jti,
            },
          }
        }
      }
      const dpopMode = await resolveAuthzPolicyDpopModeForIssuer(
        authz,
        clientResolution.clientKind,
        clientResolution.clientPolicy
      )
      return {
        ...clientResolution,
        dpopMode,
      }
    },
    /**
     * Issues a one-time DPoP nonce, persisted until consumed by proof verification on `/token`.
     */
    async createDpopNonceChallenge(ttlMs) {
      const nonce$ = context.providers.get('nonce-provider')
      const nonceStore$ = context.providers.get('nonce-store-provider')
      const dpopNonce = await nonce$.generate({ nonce_expires_in: ttlMs })
      await nonceStore$.save(dpopNonce)
      return dpopNonce.nonce
    },
    /**
     * OAuth token response for supported grant types. Pre-authorized code: validates optional DPoP
     * proof + nonce + jti, redeems the code, mints JWT access token (bearer or DPoP-bound via `cnf.jkt`).
     */
    async createAccessToken(authz, tokenRequest, options) {
      switch (tokenRequest.grant_type) {
        case 'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
          const option = options as TokenRequestOptions[GrantType.PreAuthorizedCode]

          // Optional DPoP at token endpoint: verify proof first, then optional AS nonce and jti replay protection.
          const verifiedDpopProof = option?.dpopProof
            ? await dpopProof$.verifyProof(option.dpopProof.proofJwt, {
                htm: option.dpopProof.htm,
                htu: option.dpopProof.htu,
              } satisfies DPoPProofVerifyContext)
            : undefined
          if (verifiedDpopProof) {
            if (option?.dpopProof?.nonceRequired) {
              const nonceStore$ = context.providers.get('nonce-store-provider')
              if (!verifiedDpopProof.nonce) {
                throw err('use_dpop_nonce', {
                  message: 'Authorization server requires nonce in DPoP proof.',
                })
              }
              const nonce = Nonce({ nonce: verifiedDpopProof.nonce })
              const consumed = await nonceStore$.consume(nonce)
              if (!consumed) {
                throw err('use_dpop_nonce', {
                  message: 'Authorization server requires nonce in DPoP proof.',
                })
              }
            }
            const isNewJti = await dpopProofJtiStore$.saveIfAbsent(
              verifiedDpopProof.jwkThumbprint,
              verifiedDpopProof.jti,
              { ttlMs: dpopProof$.proofJtiTtlMs }
            )
            if (!isNewJti) {
              throw err('invalid_dpop_proof', {
                message: 'DPoP proof JWT jti has already been used.',
              })
            }
          }
          // Check pre-code validity
          const credentialConfigurationIds = await codeStore$.consume(
            tokenRequest['pre-authorized_code'],
            tokenRequest.tx_code
          )
          if (!credentialConfigurationIds) {
            throw err('invalid_grant', {
              message:
                'The provided pre-authorized code is invalid or no credential configurations were found for the provided pre-authorized code.',
            })
          }
          const ttlSec = option?.ttlSec ?? 86400

          const keyAlg = options?.alg ?? 'ES256'
          // Authz access token (data)
          // for JWK privateKey
          const jwtHeader = {
            alg: keyAlg,
            typ: 'JWT',
          }
          const jwtPayload = await accessToken$.createTokenPayload(
            authz,
            tokenRequest['pre-authorized_code'],
            {
              ttlSec: option?.ttlSec,
              ...(option?.clientId ? { clientId: option.clientId } : {}),
              ...(verifiedDpopProof ? { cnf: { jkt: verifiedDpopProof.jwkThumbprint } } : {}),
            }
          )
          // sign with issuer private key
          const signature = await authzKey$.sign(authz, keyAlg, jwtPayload, jwtHeader)
          if (!signature) {
            throw err('internal_server_error', {
              message: 'Cannot sign access token.',
            })
          }
          // format JWT components
          const encode = (x: unknown) => base64url.encode(JSON.stringify(x))
          const accessToken = `${encode(jwtHeader)}.${encode(jwtPayload)}.${signature}`
          const accessTokenHash = calculateAccessTokenHash(accessToken)

          await issuanceContextStore$.save(accessTokenHash, credentialConfigurationIds, ttlSec)

          // Create Token Response
          return {
            access_token: accessToken,
            token_type: verifiedDpopProof ? 'DPoP' : 'bearer',
            expires_in: option?.ttlSec ?? 86400,
          }
        }
        case 'authorization_code': {
          // TODO: Implement authorization code flow
          throw err('unsupported_grant_type', {
            message: 'Authorization code flow is not supported.',
          })
        }
        default: {
          throw err('invalid_request', {
            message: `Unsupported grant type: ${tokenRequest.grant_type}`,
          })
        }
      }
    },
    /**
     * @returns `true` when {@link verifyAccessTokenPayload} succeeds; throws the same errors on failure.
     */
    async verifyAccessToken(authz, accessToken: string, options): Promise<boolean> {
      await verifyAccessTokenPayload(authz, accessToken, options)
      return true
    },
    /** @see {@link AuthzFlow.verifyAccessTokenPayload} */
    verifyAccessTokenPayload: verifyAccessTokenPayload,
    /** @see {@link AuthzFlow.verifyDpopBoundAccessToken} */
    verifyDpopBoundAccessToken: verifyDpopBoundAccessToken,
  }
}

export {
  AuthorizationServerIssuer,
  AuthorizationServerMetadata,
} from './authorization-server.types'
export { TokenRequest as AuthzTokenRequest } from './token-request.types'
