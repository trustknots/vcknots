import assert from 'node:assert/strict'
import { after, beforeEach, describe, it } from 'node:test'

import { initializeContext } from '../src/vcknots.context'

describe('vcknots.context', () => {
  const envSnapshot = { ...process.env }

  beforeEach(() => {
    // biome-ignore lint/performance/noDelete: <explanation>
    delete process.env.NODE_ENV
    // biome-ignore lint/performance/noDelete: <explanation>
    delete process.env.VCKNOTS_DEBUG
    // biome-ignore lint/performance/noDelete: <explanation>
    delete process.env.VCKNOTS_ALLOW_INSECURE_HTTP
  })

  after(() => {
    process.env = { ...envSnapshot }
  })

  describe('initializeContext', () => {
    it('should resolve default options', () => {
      const actual = initializeContext()

      assert.equal(actual.options?.debug, false)
      assert.equal(actual.options?.allowInsecureHttp, false)
    })

    it('should enable debug from environment variable', () => {
      process.env.VCKNOTS_DEBUG = 'true'

      const actual = initializeContext()

      assert.equal(actual.options?.debug, true)
    })

    it('should enable debug from explicit option', () => {
      process.env.NODE_ENV = 'development'

      const actual = initializeContext({
        debug: true,
      })

      assert.equal(actual.options?.debug, true)
    })

    it('should disable debug in production even if environment variable is enabled', () => {
      process.env.NODE_ENV = 'production'
      process.env.VCKNOTS_DEBUG = 'true'

      const actual = initializeContext()

      assert.equal(actual.options?.debug, false)
    })

    it('should disable debug in production even if explicit option is enabled', () => {
      process.env.NODE_ENV = 'production'

      const actual = initializeContext({
        debug: true,
      })

      assert.equal(actual.options?.debug, false)
    })

    it('should allow insecure http from environment variable', () => {
      process.env.NODE_ENV = 'development'
      process.env.VCKNOTS_ALLOW_INSECURE_HTTP = 'true'

      const actual = initializeContext()

      assert.equal(actual.options?.allowInsecureHttp, true)
    })

    it('should allow insecure http from explicit option', () => {
      process.env.NODE_ENV = 'development'

      const actual = initializeContext({
        allowInsecureHttp: true,
      })

      assert.equal(actual.options?.allowInsecureHttp, true)
    })

    it('should disable insecure http in production even if environment variable is enabled', () => {
      process.env.NODE_ENV = 'production'
      process.env.VCKNOTS_ALLOW_INSECURE_HTTP = 'true'

      const actual = initializeContext()

      assert.equal(actual.options?.allowInsecureHttp, false)
    })

    it('should disable insecure http in production even if explicit option is enabled', () => {
      process.env.NODE_ENV = 'production'

      const actual = initializeContext({
        allowInsecureHttp: true,
      })

      assert.equal(actual.options?.allowInsecureHttp, false)
    })
  })
})
