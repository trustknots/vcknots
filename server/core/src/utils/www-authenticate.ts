export type BearerChallengeError = 'invalid_request' | 'invalid_token' | 'insufficient_scope'
export type DpopChallengeError =
  | 'invalid_request'
  | 'invalid_token'
  | 'invalid_dpop_proof'
  | 'use_dpop_nonce'

export type BearerChallengeOptions = {
  realm: string
  error?: BearerChallengeError
  errorDescription?: string
  errorUri?: string
  scope?: string
}

const escapeQuotedString = (value: string) =>
  value.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/[\r\n]+/g, ' ')

const quoteAuthParam = (name: string, value: string) => `${name}="${escapeQuotedString(value)}"`

export const buildBearerAuthenticateHeader = ({
  realm,
  error,
  errorDescription,
  errorUri,
  scope,
}: BearerChallengeOptions) => {
  const params = [quoteAuthParam('realm', realm)]

  if (error) {
    params.push(quoteAuthParam('error', error))
  }
  if (errorDescription) {
    params.push(quoteAuthParam('error_description', errorDescription))
  }
  if (errorUri) {
    params.push(quoteAuthParam('error_uri', errorUri))
  }
  if (scope) {
    params.push(quoteAuthParam('scope', scope))
  }

  return `Bearer ${params.join(', ')}`
}

export type DpopChallengeOptions = {
  realm: string
  error?: DpopChallengeError
  errorDescription?: string
  errorUri?: string
}

export const buildDpopAuthenticateHeader = ({
  realm,
  error,
  errorDescription,
  errorUri,
}: DpopChallengeOptions) => {
  const params = [quoteAuthParam('realm', realm)]

  if (error) {
    params.push(quoteAuthParam('error', error))
  }
  if (errorDescription) {
    params.push(quoteAuthParam('error_description', errorDescription))
  }
  if (errorUri) {
    params.push(quoteAuthParam('error_uri', errorUri))
  }

  return `DPoP ${params.join(', ')}`
}
