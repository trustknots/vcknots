import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { initializeContext } from '@trustknots/vcknots'
import { createIssueRouter } from '../src/routes/issue.ts'

const baseUrl = 'https://issuer.example.com'
const context = initializeContext()
const issueApp = createIssueRouter(context, baseUrl)

const postCredential = (authorization?: string, body = '{}') =>
  issueApp.request('/credentials', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(authorization ? { Authorization: authorization } : {}),
    },
    body,
  })

describe('createIssueRouter()', () => {
  it('Authorization ヘッダがない場合は不正な JSON より先に WWW-Authenticate challenge を返す', async () => {
    const response = await postCredential(undefined, '{')
    const body = await response.json()

    assert.equal(response.status, 401)
    assert.equal(response.headers.get('WWW-Authenticate'), `Bearer realm="${baseUrl}"`)
    assert.deepEqual(body, {
      error: 'invalid_token',
      error_description: 'Access token is required.',
    })
  })

  it('小文字 bearer の invalid token は不正な JSON より先に 401 を返す', async () => {
    const response = await postCredential('bearer opaque-token', '{')
    const body = await response.json()

    assert.equal(response.status, 401)
    assert.equal(
      response.headers.get('WWW-Authenticate'),
      `Bearer realm="${baseUrl}", error="invalid_token", error_description="Access token is not a valid JWT."`
    )
    assert.deepEqual(body, {
      error: 'invalid_token',
      error_description: 'Access token is not a valid JWT.',
    })
  })

  it('DPoP scheme は明示的に拒否する', async () => {
    const response = await postCredential('DPoP opaque-token')
    const body = await response.json()

    assert.equal(response.status, 401)
    assert.equal(response.headers.get('WWW-Authenticate'), `Bearer realm="${baseUrl}"`)
    assert.deepEqual(body, {
      error: 'invalid_token',
      error_description: 'DPoP access tokens are not supported by this credential endpoint.',
    })
  })

  it('Bearer と DPoP 以外の scheme は拒否する', async () => {
    const response = await postCredential('Basic opaque-token')
    const body = await response.json()

    assert.equal(response.status, 401)
    assert.equal(response.headers.get('WWW-Authenticate'), `Bearer realm="${baseUrl}"`)
    assert.deepEqual(body, {
      error: 'invalid_token',
      error_description: 'Authorization header must use Bearer or DPoP scheme.',
    })
  })

  it('token に空白を含む Authorization ヘッダは malformed として拒否する', async () => {
    const response = await postCredential('Bearer abc def')
    const body = await response.json()

    assert.equal(response.status, 401)
    assert.equal(response.headers.get('WWW-Authenticate'), `Bearer realm="${baseUrl}"`)
    assert.deepEqual(body, {
      error: 'invalid_token',
      error_description: 'Authorization header must use Bearer or DPoP scheme.',
    })
  })
})
