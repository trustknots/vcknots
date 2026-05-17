import type {
  AuthorizationServerIssuer,
  AuthzFlow,
  DPoPMode,
} from '@trustknots/vcknots/authz'

export type AuthzOAuthPolicyClientKind = 'anonymous_client' | 'default_client'

const DEFAULT_DPOP_MODE: DPoPMode = 'off'

const hasValue = (value: unknown): boolean => typeof value === 'string' && value.trim().length > 0

export const resolveTokenRequestPolicyClient = (
  requestData: Record<string, unknown>
): AuthzOAuthPolicyClientKind =>
  hasValue(requestData.client_id) || hasValue(requestData.client_assertion)
    ? 'default_client'
    : 'anonymous_client'

export const resolveAuthzPolicyDpopMode = async (
  authzFlow: Pick<AuthzFlow, 'findAuthzOAuthPolicy'>,
  authz: AuthorizationServerIssuer,
  clientKind: AuthzOAuthPolicyClientKind
): Promise<DPoPMode> => {
  const policy = await authzFlow.findAuthzOAuthPolicy(authz)
  const senderConstraint = policy?.[clientKind]?.senderConstrainedAccessToken

  if (!senderConstraint) return DEFAULT_DPOP_MODE
  if (senderConstraint.method === 'none' || senderConstraint.method === 'mtls') {
    return DEFAULT_DPOP_MODE
  }

  return senderConstraint.dpop?.mode ?? DEFAULT_DPOP_MODE
}
