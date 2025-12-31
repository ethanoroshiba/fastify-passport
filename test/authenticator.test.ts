import assert from 'node:assert'
import { describe, test } from 'node:test'
import Authenticator from '../src/Authenticator'
import {
  CHALLENGE_401_INVALID_CREDENTIALS,
  getConfiguredTestServer,
  getRegisteredTestServer,
  TestStrategy
} from './helpers'
import { Strategy } from '../src/strategies'

// Mock logger for tests
const mockLogger = {
  trace: () => {},
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
  fatal: () => {}
}

describe('Authenticator edge cases', () => {
  test('should throw error when no serializer succeeds', async () => {
    const fastifyPassport = new Authenticator()

    fastifyPassport.registerUserSerializer(async () => {
      throw 'pass' // eslint-disable-line no-throw-literal
    })
    fastifyPassport.registerUserSerializer(async () => {
      throw 'pass' // eslint-disable-line no-throw-literal
    })

    const { server } = getConfiguredTestServer()

    try {
      await fastifyPassport.serializeUser({ name: 'test' }, server.inject as any)
      assert.fail('Should have thrown an error')
    } catch (error: any) {
      assert.ok(error.message.includes('Failed to serialize user into session'))
      assert.ok(error.message.includes('Tried 2 serializers'))
    }
  })

  test('should use options.assignProperty instead of default user property in authorize', async () => {
    const { server, fastifyPassport } = getConfiguredTestServer()

    server.post(
      '/authorize',
      { preValidation: fastifyPassport.authorize('test', { assignProperty: 'account' }) },
      async (request: any, reply) => {
        reply.send({ account: request.account })
      }
    )

    const response = await server.inject({
      method: 'POST',
      payload: { login: 'test', password: 'test' },
      url: '/authorize'
    })

    assert.strictEqual(response.statusCode, 200)
    const body = response.json()
    assert.ok(body.account)
    assert.strictEqual(body.account.name, 'test')
  })

  test('should handle authorize with callback function as second parameter', async () => {
    const { server, fastifyPassport } = getConfiguredTestServer()

    server.post('/authorize', async (request: any, reply) => {
      const handler = fastifyPassport.authorize(
        'test',
        async (req: any, rep: any, err: any, user: any) => {
          if (err) {
            return rep.status(500).send({ error: err.message })
          }
          rep.send({ authorizedUser: user })
        }
      )
      return handler.call(server, request, reply)
    })

    const response = await server.inject({
      method: 'POST',
      payload: { login: 'test', password: 'test' },
      url: '/authorize'
    })

    assert.strictEqual(response.statusCode, 200)
    const body = response.json()
    assert.ok(body.authorizedUser)
  })

  test('should use default authInfo transformer when no transformers are registered', async () => {
    const fastifyPassport = new Authenticator()
    const { server } = getConfiguredTestServer()

    const info = { message: 'test info' }
    const result = await fastifyPassport.transformAuthInfo(info, server.inject as any)

    assert.deepStrictEqual(result, info)
  })

  test('should transform authInfo with registered transformer', async () => {
    const fastifyPassport = new Authenticator()

    fastifyPassport.registerAuthInfoTransformer(async (info) => {
      return { ...info, transformed: true }
    })

    const { server } = getConfiguredTestServer()
    const info = { message: 'test info' }
    const result = await fastifyPassport.transformAuthInfo(info, server.inject as any)

    assert.strictEqual(result.message, 'test info')
    assert.strictEqual(result.transformed, true)
  })

  test('should skip infoTransformers that throw "pass"', async () => {
    const fastifyPassport = new Authenticator()

    fastifyPassport.registerAuthInfoTransformer(async () => {
      throw 'pass' // eslint-disable-line no-throw-literal
    })

    fastifyPassport.registerAuthInfoTransformer(async (info) => {
      return { ...info, transformed: true }
    })

    const { server } = getConfiguredTestServer()
    const info = { message: 'test info' }
    const result = await fastifyPassport.transformAuthInfo(info, server.inject as any)

    assert.strictEqual(result.message, 'test info')
    assert.strictEqual(result.transformed, true)
  })

  test('should throw error from transformer if not "pass"', async () => {
    const fastifyPassport = new Authenticator()

    fastifyPassport.registerAuthInfoTransformer(async () => {
      throw new Error('Transformer error')
    })

    const { server } = getConfiguredTestServer()
    const info = { message: 'test info' }

    try {
      await fastifyPassport.transformAuthInfo(info, server.inject as any)
      assert.fail('Should have thrown an error')
    } catch (error: any) {
      assert.strictEqual(error.message, 'Transformer error')
    }
  })
})

describe('Authenticator.authenticateRequest', () => {
  test('should return success result when authentication succeeds with single strategy', async () => {
    const { fastifyPassport } = getConfiguredTestServer()

    const mockRequest = {
      body: { login: 'test', password: 'test' },
      passport: fastifyPassport,
      isAuthenticated: () => false,
      log: mockLogger,
      logIn: async function(user: any, options: any) {
        this.user = user
      }
    } as any

    const mockReply = {
      code: () => mockReply,
      send: () => mockReply,
      redirect: () => mockReply
    } as any

    const result = await fastifyPassport.authenticateRequest('test', mockRequest, mockReply)

    assert.strictEqual(result.ok, true)
    assert.strictEqual(result.strategy, 'test')
    assert.ok(result.user)
    assert.strictEqual((result.user as any).name, 'test')
    assert.strictEqual(result.error, undefined)
    assert.strictEqual(result.status, undefined)
    assert.strictEqual(result.challenges, undefined)
    assert.ok(result.info)
    assert.strictEqual((result.info as any).message, 'Authentication successful')
  })

  test('should return failure result when authentication fails with single strategy', async () => {
    const { fastifyPassport } = getConfiguredTestServer()

    const mockRequest = {
      body: { login: 'wrong', password: 'wrong' },
      passport: {},
      isAuthenticated: () => false,
      log: mockLogger
    } as any

    const mockReply = {
      code: () => mockReply,
      send: () => mockReply,
      redirect: () => mockReply
    } as any

    const result = await fastifyPassport.authenticateRequest('test', mockRequest, mockReply)

    assert.strictEqual(result.ok, false)
    assert.strictEqual(result.strategy, 'test')
    assert.strictEqual(result.user, undefined)
    assert.strictEqual(result.info, undefined)
    assert.strictEqual(result.status, 401)
    assert.ok(result.challenges)
    assert.strictEqual(result.challenges.length, 1)
    assert.strictEqual(result.challenges[0], 'Invalid credentials')
  })

  test('should try strategies in order and stop at first success', async () => {
    const { fastifyPassport } = getRegisteredTestServer()

    // Register a strategy that always fails
    class AlwaysFailStrategy extends Strategy {
      authenticate() {
        this.fail('Always fails', 401)
      }
    }

    // Register a strategy that always succeeds
    class AlwaysSucceedStrategy extends Strategy {
      authenticate() {
        this.success({ name: 'test', id: '1' }, { message: 'Success' })
      }
    }

    const failStrategy = new AlwaysFailStrategy('fail-first')
    const successStrategy = new AlwaysSucceedStrategy('success-second')

    const mockRequest = {
      body: { login: 'test', password: 'test' },
      passport: fastifyPassport,
      isAuthenticated: () => false,
      log: mockLogger,
      logIn: async function(user: any, options: any) {
        this.user = user
      }
    } as any

    const mockReply = {
      code: () => mockReply,
      send: () => mockReply,
      redirect: () => mockReply
    } as any

    const result = await fastifyPassport.authenticateRequest(
      [failStrategy, successStrategy],
      mockRequest,
      mockReply
    )

    assert.strictEqual(result.ok, true)
    assert.strictEqual(result.strategy, 'success-second')
    assert.ok(result.user)
    assert.strictEqual(result.status, undefined)
    assert.strictEqual(result.challenges, undefined)
    assert.strictEqual(result.error, undefined)
    assert.ok(result.info)
  })

  test('should return failure with all challenges when all strategies fail', async () => {
    const { fastifyPassport } = getRegisteredTestServer()

    // Register test strategies
    fastifyPassport.use('test', new TestStrategy('test'))
    fastifyPassport.use('test2', new TestStrategy('test2'))

    const mockRequest = {
      body: {}, // Wrong credentials - both will fail
      passport: {},
      isAuthenticated: () => false,
      log: mockLogger
    } as any

    const mockReply = {
      code: () => mockReply,
      send: () => mockReply,
      redirect: () => mockReply
    } as any

    const result = await fastifyPassport.authenticateRequest(['test', 'test2'], mockRequest, mockReply)

    assert.strictEqual(result.ok, false)
    assert.strictEqual(result.strategy, 'test2') // Last strategy attempted
    assert.strictEqual(result.user, undefined)
    assert.strictEqual(result.info, undefined)
    assert.strictEqual(result.status, 401) // Last failure status
    assert.ok(result.challenges)
    assert.strictEqual(result.challenges.length, 2)
    assert.strictEqual(result.challenges[0], CHALLENGE_401_INVALID_CREDENTIALS)
    assert.strictEqual(result.challenges[1], CHALLENGE_401_INVALID_CREDENTIALS)
  })

  test('should handle strategy errors and include them in result', async () => {
    const { fastifyPassport } = getRegisteredTestServer()

    class ErrorStrategy extends Strategy {
      authenticate(_request: any, _options?: { pauseStream?: boolean }) {
        this.error(new Error('Strategy internal error'))
      }
    }

    fastifyPassport.use('error-strategy', new ErrorStrategy('error-strategy'))

    const mockRequest = {
      body: {},
      passport: {},
      isAuthenticated: () => false,
      log: mockLogger
    } as any

    const mockReply = {
      code: () => mockReply,
      send: () => mockReply,
      redirect: () => mockReply
    } as any

    const result = await fastifyPassport.authenticateRequest('error-strategy', mockRequest, mockReply)

    assert.strictEqual(result.ok, false)
    assert.strictEqual(result.strategy, 'error-strategy')
    assert.strictEqual(result.user, undefined)
    assert.strictEqual(result.info, undefined)
    assert.ok(result.error)
    assert.strictEqual(result.error.message, 'Strategy internal error')
  })

  test('should handle options parameter', async () => {
    const { fastifyPassport } = getConfiguredTestServer()

    const mockRequest = {
      body: { login: 'test', password: 'test' },
      passport: fastifyPassport,
      isAuthenticated: () => false,
      session: {
        set: () => {},
        get: () => undefined
      },
      log: mockLogger,
      logIn: async function(user: any, options: any) {
        this.user = user
      }
    } as any

    const mockReply = {
      code: () => mockReply,
      send: () => mockReply,
      redirect: () => mockReply
    } as any

    const result = await fastifyPassport.authenticateRequest('test', mockRequest, mockReply, { session: false })

    assert.strictEqual(result.ok, true)
    assert.strictEqual(result.strategy, 'test')
    assert.ok(result.info)
    assert.strictEqual((result.info as any).message, 'Authentication successful')
  })

  test('should not include sensitive data in error result', async () => {
    const { fastifyPassport } = getRegisteredTestServer()

    const SENSITIVE_JWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'
    const SENSITIVE_PASSWORD = 'SuperSecret123!'
    const SENSITIVE_TOKEN_FIELD = 'secret-token-12345'
    const SENSITIVE_API_KEY_FIELD = 'api-key-secret'
    const SENSITIVE_EMAIL = 'user@example.com'
    const SENSITIVE_BEARER_TOKEN = 'abc123def456ghi789jkl'
    const SENSITIVE_API_KEY = 'sk_live_51Hfr2H4h3h3h3h3h3h3h3h'
    const REDACTED_MARKER = '[REDACTED]'

    class SensitiveErrorStrategy extends Strategy {
      authenticate(_request: any, _options?: { pauseStream?: boolean }) {
        const error = new Error(`Authentication failed with token: ${SENSITIVE_JWT} and password=${SENSITIVE_PASSWORD}`) as any
        error.token = SENSITIVE_TOKEN_FIELD
        error.apiKey = SENSITIVE_API_KEY_FIELD
        error.userEmail = SENSITIVE_EMAIL
        this.error(error)
      }
    }

    fastifyPassport.use('sensitive', new SensitiveErrorStrategy('sensitive'))

    const mockRequest = {
      body: {},
      passport: fastifyPassport,
      isAuthenticated: () => false,
      log: mockLogger
    } as any

    const mockReply = {
      code: () => mockReply,
      send: () => mockReply,
      redirect: () => mockReply
    } as any

    const result = await fastifyPassport.authenticateRequest('sensitive', mockRequest, mockReply)

    assert.strictEqual(result.ok, false)
    assert.ok(result.error)

    // Test the error message directly (Error.message is not enumerable so JSON.stringify doesn't include it)
    const errorMessage = result.error.message

    // The error object should not contain sensitive fields in the sanitized result
    const resultStr = JSON.stringify(result)
    assert.ok(!resultStr.includes(SENSITIVE_TOKEN_FIELD))
    assert.ok(!resultStr.includes(SENSITIVE_API_KEY_FIELD))
    assert.ok(!resultStr.includes(SENSITIVE_EMAIL))

    // Test that error messages are sanitized
    assert.ok(!errorMessage.includes(SENSITIVE_JWT), 'JWT should be redacted')
    assert.ok(!errorMessage.includes(SENSITIVE_PASSWORD), 'Password should be redacted')
    assert.ok(errorMessage.includes(REDACTED_MARKER), 'Should contain redaction marker')

    // Test sensitive data in challenges (fail messages)
    class SensitiveChallengeStrategy extends Strategy {
      authenticate(_request: any, _options?: { pauseStream?: boolean }) {
        this.fail(`Invalid Bearer ${SENSITIVE_BEARER_TOKEN} with api_key=${SENSITIVE_API_KEY}`)
      }
    }
    fastifyPassport.use('challenge', new SensitiveChallengeStrategy('challenge'))

    const challengeResult = await fastifyPassport.authenticateRequest('challenge', mockRequest, mockReply)
    const challenges = challengeResult.challenges || []
    const challengeStr = challenges.join(' ')
    assert.ok(!challengeStr.includes(SENSITIVE_BEARER_TOKEN), 'Bearer token should be redacted from challenge')
    assert.ok(!challengeStr.includes(SENSITIVE_API_KEY), 'API key should be redacted from challenge')
    assert.ok(challengeStr.includes(REDACTED_MARKER), 'Challenge should contain redaction marker')
  })

  test('should not automatically send a response', async () => {
    const { fastifyPassport } = getConfiguredTestServer()

    let replySent = false
    let replyRedirected = false

    const mockRequest = {
      body: { login: 'test', password: 'test' },
      passport: fastifyPassport,
      isAuthenticated: () => false,
      log: mockLogger,
      logIn: async function(user: any, options: any) {
        this.user = user
      }
    } as any

    const mockReply = {
      code: () => mockReply,
      send: (data: any) => {
        replySent = true
        return mockReply
      },
      redirect: (url: string) => {
        replyRedirected = true
        return mockReply
      }
    } as any

    const result = await fastifyPassport.authenticateRequest('test', mockRequest, mockReply)

    assert.strictEqual(result.ok, true)
    assert.strictEqual(replySent, false, 'Should not send response automatically')
    assert.strictEqual(replyRedirected, false, 'Should not redirect automatically')
    assert.strictEqual(result.info?.message, 'Authentication successful')
  })

  test('should handle unknown strategy name', async () => {
    const { fastifyPassport } = getRegisteredTestServer()

    const mockRequest = {
      body: {},
      passport: {},
      isAuthenticated: () => false,
      log: mockLogger
    } as any

    const mockReply = {
      code: () => mockReply,
      send: () => mockReply,
      redirect: () => mockReply
    } as any

    const result = await fastifyPassport.authenticateRequest('unknown-strategy', mockRequest, mockReply)
    assert.ok(result.error?.message.includes('Unknown authentication strategy'))
    assert.ok(result.error?.message.includes('unknown-strategy'))
  })

  test('should handle failure without challenge message', async () => {
    const { fastifyPassport } = getRegisteredTestServer()

    // Inline strategy that fails without a challenge message
    class FailNoChallenge extends Strategy {
      authenticate() {
        this.fail(401)
      }
    }

    fastifyPassport.use('fail-no-challenge', new FailNoChallenge('fail-no-challenge'))

    const mockRequest = {
      body: {},
      passport: {},
      isAuthenticated: () => false,
      log: mockLogger
    } as any

    const mockReply = {
      code: () => mockReply,
      send: () => mockReply,
      redirect: () => mockReply
    } as any

    const result = await fastifyPassport.authenticateRequest('fail-no-challenge', mockRequest, mockReply)

    assert.strictEqual(result.ok, false)
    assert.strictEqual(result.strategy, 'fail-no-challenge')
    assert.strictEqual(result.info, undefined)
    assert.strictEqual(result.status, 401)
    // Should have challenges array but might be empty or contain undefined
    assert.ok(result.challenges)
  })

  test('should handle strategy that calls pass()', async () => {
    const { fastifyPassport } = getRegisteredTestServer()

    class PassStrategy extends Strategy {
      authenticate(_request: any, _options?: { pauseStream?: boolean }) {
        this.pass()
      }
    }

    fastifyPassport.use('pass-strategy', new PassStrategy('pass-strategy'))

    const mockRequest = {
      body: {},
      passport: {},
      isAuthenticated: () => false,
      log: mockLogger
    } as any

    const mockReply = {
      code: () => mockReply,
      send: () => mockReply,
      redirect: () => mockReply
    } as any

    const result = await fastifyPassport.authenticateRequest('pass-strategy', mockRequest, mockReply)

    // When a strategy passes, it should be treated as neither success nor failure
    // The behavior here depends on implementation, but typically it means the strategy
    // deferred the decision, so we might expect ok: false with no specific error
    assert.strictEqual(result.ok, false)
    assert.strictEqual(result.strategy, 'pass-strategy')
    assert.strictEqual(result.user, undefined)
    assert.strictEqual(result.info, undefined)
    assert.strictEqual(result.error, undefined)
    // Pass shouldn't add challenges or status codes
    assert.ok(!result.challenges || result.challenges.length === 0)
  })
})
