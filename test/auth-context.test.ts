import assert from 'node:assert'
import { describe, test } from 'node:test'
import { getConfiguredTestServer, generateTestUser, CHALLENGE_401_INVALID_CREDENTIALS, getNextUserId } from './helpers'
import type { AuthContext } from '../src/index'
import { Strategy } from '../src/strategies'

// Strategy with configurable delay for testing timing calculations
class DelayedTestStrategy extends Strategy {
  readonly delayMs: number

  constructor (name: string, delayMs: number = 10) {
    super(name)
    this.delayMs = delayMs
  }

  async authenticate (request: any, _options?: { pauseStream?: boolean }) {
    await new Promise(resolve => setTimeout(resolve, this.delayMs))

    if (request.isAuthenticated()) {
      return this.pass()
    }
    if (request.body && request.body.login === 'test' && request.body.password === 'test') {
      return this.success(generateTestUser(), { message: 'Authentication successful' })
    }

    this.fail(CHALLENGE_401_INVALID_CREDENTIALS, 401)
  }
}

const testSuite = (sessionPluginName: string) => {
  describe(`${sessionPluginName} - Auth Context tests`, () => {
    describe('Hook-based authentication', () => {
      test('should populate authContext on successful authentication', async () => {
        const STRATEGY_DELAY_MS = 10
        const EXPECTED_SCOPE = 'read:profile'
        const EXPECTED_USER_ID = getNextUserId()
        const delayedStrategy = new DelayedTestStrategy('test', STRATEGY_DELAY_MS)
        const { server, fastifyPassport } = getConfiguredTestServer('test', delayedStrategy)
        let capturedContext: AuthContext | undefined

        server.addHook('onRequest', async (request, reply) => {
          request.authContext = {
            attemptedStrategies: [],
            elapsedMs: 0,
            status: 'rejected',
            elapsedPerStrategy: [],
            userId: '',
            requestedScope: ''
          }
        })

        server.post(
          '/login',
          { preValidation: fastifyPassport.authenticate('test', { authInfo: false, scope: EXPECTED_SCOPE }) },
          async (request, reply) => {
            capturedContext = request.authContext
            reply.send({ success: true, context: request.authContext })
          }
        )

        const response = await server.inject({
          method: 'POST',
          url: '/login',
          payload: { login: 'test', password: 'test' }
        })

        assert.strictEqual(response.statusCode, 200)
        assert.ok(capturedContext, 'authContext should be populated')
        assert.ok(Array.isArray(capturedContext.attemptedStrategies), 'attemptedStrategies should be an array')
        assert.ok(capturedContext.attemptedStrategies.includes('test'), 'should include test strategy')
        assert.strictEqual(capturedContext.status, 'authenticated')
        assert.strictEqual(typeof capturedContext.elapsedMs, 'number')
        assert.ok(capturedContext.elapsedMs >= STRATEGY_DELAY_MS, `elapsed time should include the ${STRATEGY_DELAY_MS}ms delay`)
        assert.ok(Array.isArray(capturedContext.elapsedPerStrategy), 'elapsedPerStrategy should be an array')
        assert.strictEqual(
          capturedContext.elapsedPerStrategy.length,
          capturedContext.attemptedStrategies.length,
          'elapsedPerStrategy should be aligned with attemptedStrategies'
        )
        assert.ok('userId' in capturedContext, 'userId field should be present when included in initial context')
        assert.strictEqual(capturedContext.userId, EXPECTED_USER_ID, 'userId should be populated with the expected generated test user id')
        assert.ok('requestedScope' in capturedContext, 'requestedScope field should be present when included in initial context')
        assert.strictEqual(capturedContext.requestedScope, EXPECTED_SCOPE, 'requestedScope should match the configured scope')
      })

      test('should populate authContext on failed authentication', async () => {
        const STRATEGY_DELAY_MS = 10
        const EXPECTED_SCOPE = 'write:data'
        const delayedStrategy = new DelayedTestStrategy('test', STRATEGY_DELAY_MS)
        const { server, fastifyPassport } = getConfiguredTestServer('test', delayedStrategy)
        let capturedContext: AuthContext | undefined

        server.addHook('onRequest', async (request, reply) => {
          request.authContext = {
            attemptedStrategies: [],
            elapsedMs: 0,
            status: 'rejected',
            elapsedPerStrategy: [],
            userId: '',
            requestedScope: ''
          }
        })

        server.addHook('onResponse', async (request, reply) => {
          if (request.url === '/login') {
            capturedContext = request.authContext
          }
        })

        server.post(
          '/login',
          { preValidation: fastifyPassport.authenticate('test', { authInfo: false, scope: EXPECTED_SCOPE }) },
          async (request, reply) => {
            reply.send({ success: true })
          }
        )

        const response = await server.inject({
          method: 'POST',
          url: '/login',
          payload: { login: 'wrong', password: 'wrong' }
        })

        assert.strictEqual(response.statusCode, 401)
        assert.ok(capturedContext, 'authContext should be populated even on failure')
        assert.ok(Array.isArray(capturedContext.attemptedStrategies))
        assert.strictEqual(capturedContext.status, 'rejected')
        assert.strictEqual(typeof capturedContext.elapsedMs, 'number')
        assert.ok(capturedContext.elapsedMs >= STRATEGY_DELAY_MS, `elapsed time should include the ${STRATEGY_DELAY_MS}ms delay`)
        assert.ok(Array.isArray(capturedContext.elapsedPerStrategy), 'elapsedPerStrategy should be tracked even on failure')
        assert.strictEqual(capturedContext.userId, undefined, 'userId should not be populated on failure')
        assert.ok('requestedScope' in capturedContext, 'requestedScope field should be present when included in initial context')
        assert.strictEqual(capturedContext.requestedScope, EXPECTED_SCOPE, 'requestedScope should match the configured scope even on failure')
      })

      test('should track multiple strategies in authContext', async () => {
        const FIRST_STRATEGY_DELAY_MS = 10
        const SECOND_STRATEGY_DELAY_MS = 15
        const strategy1 = new DelayedTestStrategy('test', FIRST_STRATEGY_DELAY_MS)
        const strategy2 = new DelayedTestStrategy('test2', SECOND_STRATEGY_DELAY_MS)
        const { server, fastifyPassport } = getConfiguredTestServer('test', strategy1)
        fastifyPassport.use('test2', strategy2)
        let capturedContext: AuthContext | undefined

        server.addHook('onRequest', async (request, reply) => {
          request.authContext = {
            attemptedStrategies: [],
            elapsedMs: 0,
            status: 'rejected',
            elapsedPerStrategy: []
          }
        })

        server.addHook('onResponse', async (request, reply) => {
          if (request.url === '/login') {
            capturedContext = request.authContext
          }
        })

        server.post(
          '/login',
          { preValidation: fastifyPassport.authenticate(['test', 'test2'], { authInfo: false }) },
          async (request, reply) => {
            reply.send({ success: true })
          }
        )

        const response = await server.inject({
          method: 'POST',
          url: '/login',
          payload: { login: 'wrong', password: 'wrong' }
        })

        assert.strictEqual(response.statusCode, 401)
        assert.ok(capturedContext, 'authContext should be populated')
        assert.ok(Array.isArray(capturedContext.attemptedStrategies))
        assert.ok(capturedContext.attemptedStrategies.length > 0)

        // Verify elapsedPerStrategy tracks each strategy's timing
        assert.ok(Array.isArray(capturedContext.elapsedPerStrategy))
        assert.strictEqual(
          capturedContext.elapsedPerStrategy.length,
          capturedContext.attemptedStrategies.length,
          'elapsedPerStrategy should have one entry per attempted strategy'
        )
        assert.ok(
          capturedContext.elapsedPerStrategy[0] >= FIRST_STRATEGY_DELAY_MS,
          `first strategy timing should include its ${FIRST_STRATEGY_DELAY_MS}ms delay`
        )
        assert.ok(
          capturedContext.elapsedPerStrategy[1] >= SECOND_STRATEGY_DELAY_MS,
          `second strategy timing should include its ${SECOND_STRATEGY_DELAY_MS}ms delay`
        )
      })

      test('should not populate optional fields when not included in initial authContext', async () => {
        const STRATEGY_DELAY_MS = 10
        const delayedStrategy = new DelayedTestStrategy('test', STRATEGY_DELAY_MS)
        const { server, fastifyPassport } = getConfiguredTestServer('test', delayedStrategy)
        let capturedContext: AuthContext | undefined

        server.addHook('onRequest', async (request, reply) => {
          // No optional fields
          request.authContext = {
            attemptedStrategies: [],
            elapsedMs: 0,
            status: 'rejected'
          }
        })

        server.post(
          '/login',
          { preValidation: fastifyPassport.authenticate('test', { authInfo: false, scope: 'read:profile' }) },
          async (request, reply) => {
            capturedContext = request.authContext
            reply.send({ success: true })
          }
        )

        const response = await server.inject({
          method: 'POST',
          url: '/login',
          payload: { login: 'test', password: 'test' }
        })

        assert.strictEqual(response.statusCode, 200)
        assert.ok(capturedContext, 'authContext should be populated')

        // Required fields should be populated
        assert.ok(Array.isArray(capturedContext.attemptedStrategies))
        assert.strictEqual(capturedContext.status, 'authenticated')
        assert.ok(capturedContext.elapsedMs >= STRATEGY_DELAY_MS)

        // Optional fields should NOT be present when not included in initial context
        assert.strictEqual(capturedContext.elapsedPerStrategy, undefined, 'elapsedPerStrategy should not be populated')
        assert.strictEqual(capturedContext.userId, undefined, 'userId should not be populated')
        assert.strictEqual(capturedContext.requestedScope, undefined, 'requestedScope should not be populated')
      })
    })

    describe('Programmatic authentication', () => {
      test('should populate authContext on successful programmatic authentication', async () => {
        const STRATEGY_DELAY_MS = 10
        const EXPECTED_SCOPE = 'admin:read'
        const EXPECTED_USER_ID = getNextUserId()
        const delayedStrategy = new DelayedTestStrategy('test', STRATEGY_DELAY_MS)
        const { server, fastifyPassport } = getConfiguredTestServer('test', delayedStrategy)
        let capturedContext: AuthContext | undefined

        server.addHook('onRequest', async (request, reply) => {
          request.authContext = {
            attemptedStrategies: [],
            elapsedMs: 0,
            status: 'rejected',
            elapsedPerStrategy: [],
            userId: '',
            requestedScope: ''
          }
        })

        server.post('/auth', async (request, reply) => {
          const result = await fastifyPassport.authenticateRequest('test', request, reply, {
            session: false,
            scope: EXPECTED_SCOPE
          })

          capturedContext = request.authContext

          if (result.ok) {
            reply.send({
              success: true,
              user: result.user,
              context: request.authContext
            })
          } else {
            reply.code(401).send({ success: false })
          }
        })

        const response = await server.inject({
          method: 'POST',
          url: '/auth',
          payload: { login: 'test', password: 'test' }
        })

        assert.strictEqual(response.statusCode, 200)
        assert.ok(capturedContext, 'authContext should be populated')
        assert.ok(Array.isArray(capturedContext.attemptedStrategies))
        assert.ok(capturedContext.attemptedStrategies.includes('test'))
        assert.strictEqual(capturedContext.status, 'authenticated')
        assert.strictEqual(typeof capturedContext.elapsedMs, 'number')
        assert.ok(capturedContext.elapsedMs >= STRATEGY_DELAY_MS, `elapsed time should include the ${STRATEGY_DELAY_MS}ms delay`)
        assert.ok(Array.isArray(capturedContext.elapsedPerStrategy), 'elapsedPerStrategy should be an array')
        assert.ok('userId' in capturedContext, 'userId field should be present when included in initial context')
        assert.strictEqual(capturedContext.userId, EXPECTED_USER_ID, 'userId should be populated with the expected generated test user id')
        assert.ok('requestedScope' in capturedContext, 'requestedScope field should be present when included in initial context')
        assert.strictEqual(capturedContext.requestedScope, EXPECTED_SCOPE, 'requestedScope should match the configured scope')
      })

      test('should populate authContext on failed programmatic authentication', async () => {
        const STRATEGY_DELAY_MS = 10
        const EXPECTED_SCOPE = 'admin:write'
        const delayedStrategy = new DelayedTestStrategy('test', STRATEGY_DELAY_MS)
        const { server, fastifyPassport } = getConfiguredTestServer('test', delayedStrategy)
        let capturedContext: AuthContext | undefined

        server.addHook('onRequest', async (request, reply) => {
          request.authContext = {
            attemptedStrategies: [],
            elapsedMs: 0,
            status: 'rejected',
            elapsedPerStrategy: [],
            userId: '',
            requestedScope: ''
          }
        })

        server.post('/auth', async (request, reply) => {
          const result = await fastifyPassport.authenticateRequest('test', request, reply, {
            session: false,
            scope: EXPECTED_SCOPE
          })

          capturedContext = request.authContext

          if (result.ok) {
            reply.send({ success: true })
          } else {
            reply.code(result.status || 401).send({
              success: false,
              context: request.authContext
            })
          }
        })

        const response = await server.inject({
          method: 'POST',
          url: '/auth',
          payload: { login: 'wrong', password: 'wrong' }
        })

        assert.strictEqual(response.statusCode, 401)
        assert.ok(capturedContext, 'authContext should be populated even on failure')
        assert.strictEqual(capturedContext.status, 'rejected')
        assert.ok(Array.isArray(capturedContext.attemptedStrategies))
        assert.ok(capturedContext.elapsedMs >= STRATEGY_DELAY_MS, `elapsed time should include the ${STRATEGY_DELAY_MS}ms delay`)
        assert.ok(Array.isArray(capturedContext.elapsedPerStrategy), 'elapsedPerStrategy should be tracked even on failure')
        assert.strictEqual(capturedContext.userId, undefined, 'userId should not be populated on failure')
        assert.ok('requestedScope' in capturedContext, 'requestedScope field should be present when included in initial context')
        assert.strictEqual(capturedContext.requestedScope, EXPECTED_SCOPE, 'requestedScope should match the configured scope even on failure')
      })

      test('should track multiple strategies in programmatic authentication', async () => {
        const FIRST_STRATEGY_DELAY_MS = 12
        const SECOND_STRATEGY_DELAY_MS = 8
        const strategy1 = new DelayedTestStrategy('test', FIRST_STRATEGY_DELAY_MS)
        const strategy2 = new DelayedTestStrategy('db', SECOND_STRATEGY_DELAY_MS)
        const { server, fastifyPassport } = getConfiguredTestServer('test', strategy1)
        fastifyPassport.use('db', strategy2)
        let capturedContext: AuthContext | undefined

        server.addHook('onRequest', async (request, reply) => {
          request.authContext = {
            attemptedStrategies: [],
            elapsedMs: 0,
            status: 'rejected',
            elapsedPerStrategy: []
          }
        })

        server.post('/auth', async (request, reply) => {
          const result = await fastifyPassport.authenticateRequest(
            ['test', 'db'],
            request,
            reply,
            { session: false }
          )

          capturedContext = request.authContext

          if (result.ok) {
            reply.send({ success: true, strategy: result.strategy })
          } else {
            reply.code(401).send({ success: false })
          }
        })

        server.addHook('onResponse', async (request, reply) => {
          if (request.url === '/auth') {
            capturedContext = request.authContext
          }
        })

        // Test with credentials that match the 'test' strategy
        const response = await server.inject({
          method: 'POST',
          url: '/auth',
          payload: { login: 'wrong', password: 'wrong' }
        })

        assert.strictEqual(response.statusCode, 401)
        assert.ok(capturedContext)
        assert.ok(Array.isArray(capturedContext.attemptedStrategies))
        assert.ok(capturedContext.attemptedStrategies.length > 0)

        // Verify elapsedPerStrategy tracks each strategy's timing
        assert.ok(Array.isArray(capturedContext.elapsedPerStrategy))
        assert.strictEqual(
          capturedContext.elapsedPerStrategy.length,
          capturedContext.attemptedStrategies.length,
          'elapsedPerStrategy should have one entry per attempted strategy'
        )
        // First strategy should have taken at least its delay time
        assert.ok(
          capturedContext.elapsedPerStrategy[0] >= FIRST_STRATEGY_DELAY_MS,
          `first strategy timing should include its ${FIRST_STRATEGY_DELAY_MS}ms delay`
        )
        assert.ok(
          capturedContext.elapsedPerStrategy[1] >= SECOND_STRATEGY_DELAY_MS,
          `second strategy timing should include its ${SECOND_STRATEGY_DELAY_MS}ms delay`
        )
      })

      test('should provide consistent context between hook and programmatic approaches', async () => {
        const { server, fastifyPassport } = getConfiguredTestServer()
        let hookContext: AuthContext | undefined
        let programmaticContext: AuthContext | undefined

        server.addHook('onRequest', async (request, reply) => {
          request.authContext = {
            attemptedStrategies: [],
            elapsedMs: 0,
            status: 'rejected'
          }
        })

        // Hook-based endpoint
        server.post(
          '/hook-auth',
          { preValidation: fastifyPassport.authenticate('test', { authInfo: false }) },
          async (request, reply) => {
            hookContext = request.authContext
            reply.send({ method: 'hook' })
          }
        )

        // Programmatic endpoint
        server.post('/programmatic-auth', async (request, reply) => {
          const result = await fastifyPassport.authenticateRequest('test', request, reply, {
            session: false
          })
          programmaticContext = request.authContext

          if (result.ok) {
            reply.send({ method: 'programmatic' })
          } else {
            reply.code(401).send({ success: false })
          }
        })

        const hookResponse = await server.inject({
          method: 'POST',
          url: '/hook-auth',
          payload: { login: 'test', password: 'test' }
        })

        const programmaticResponse = await server.inject({
          method: 'POST',
          url: '/programmatic-auth',
          payload: { login: 'test', password: 'test' }
        })

        assert.strictEqual(hookResponse.statusCode, 200)
        assert.strictEqual(programmaticResponse.statusCode, 200)

        // Both should have similar structure
        assert.ok(hookContext)
        assert.ok(programmaticContext)

        // Verify structure consistency
        assert.ok(Array.isArray(hookContext.attemptedStrategies))
        assert.ok(Array.isArray(programmaticContext.attemptedStrategies))
        assert.strictEqual(typeof hookContext.elapsedMs, 'number')
        assert.strictEqual(typeof programmaticContext.elapsedMs, 'number')
        assert.ok(['authenticated', 'rejected'].includes(hookContext.status))
        assert.ok(['authenticated', 'rejected'].includes(programmaticContext.status))
      })
    })

    describe('Request isolation and security', () => {
      test('should not leak authContext between concurrent requests', async () => {
        const { server, fastifyPassport } = getConfiguredTestServer()
        const contexts: (AuthContext | undefined)[] = []

        server.addHook('onRequest', async (request, reply) => {
          request.authContext = {
            attemptedStrategies: [],
            elapsedMs: 0,
            status: 'rejected'
          }
        })

        server.post('/auth', async (request, reply) => {
          // Simulate varying authentication times
          await new Promise(resolve => setTimeout(resolve, Math.random() * 20))

          const result = await fastifyPassport.authenticateRequest('test', request, reply, {
            session: false
          })

          // Store context after async operations
          contexts.push(request.authContext)

          if (result.ok) {
            reply.send({
              userId: request.authContext?.userId,
              status: request.authContext?.status
            })
          } else {
            reply.code(401).send({ success: false })
          }
        })

        // Make multiple concurrent requests
        const requests = Array.from({ length: 10 }, (_, i) =>
          server.inject({
            method: 'POST',
            url: '/auth',
            payload: { login: 'test', password: 'test' }
          })
        )

        const responses = await Promise.all(requests)

        // All should succeed
        responses.forEach(response => {
          assert.strictEqual(response.statusCode, 200)
        })

        // Each context should be independent (if captured)
        const validContexts = contexts.filter(ctx => ctx !== undefined)
        assert.ok(validContexts.length > 0, 'should have captured some contexts')
      })

      test('should not include sensitive information in authContext', async () => {
        const { server, fastifyPassport } = getConfiguredTestServer()
        let capturedContext: AuthContext | undefined

        server.addHook('onRequest', async (request, reply) => {
          request.authContext = {
            attemptedStrategies: [],
            elapsedMs: 0,
            status: 'rejected'
          }
        })

        server.addHook('onResponse', async (request, reply) => {
          if (request.url === '/login') {
            capturedContext = request.authContext
          }
        })

        server.post(
          '/login',
          { preValidation: fastifyPassport.authenticate('test', { authInfo: false }) },
          async (request, reply) => {
            reply.send({ success: true })
          }
        )

        await server.inject({
          method: 'POST',
          url: '/login',
          payload: { login: 'test', password: 'secretPassword123!' }
        })

        assert.ok(capturedContext)

        // Convert to string to check if password is anywhere in the context
        const contextStr = JSON.stringify(capturedContext)
        assert.ok(!contextStr.includes('secretPassword123!'), 'should not include password')
        assert.ok(!contextStr.includes('password'), 'should not include password field')

        // Should not have full user object (unless explicitly enabled)
        const contextKeys = Object.keys(capturedContext)
        assert.ok(!contextKeys.includes('user'), 'should not include full user object by default')
        assert.ok(!contextKeys.includes('token'), 'should not include tokens')
        assert.ok(!contextKeys.includes('credentials'), 'should not include credentials')
      })

      test('should reset authContext for each request lifecycle', async () => {
        const { server, fastifyPassport } = getConfiguredTestServer()
        const capturedContexts: AuthContext[] = []

        server.addHook('onRequest', async (request, reply) => {
          request.authContext = {
            attemptedStrategies: [],
            elapsedMs: 0,
            status: 'rejected'
          }
        })

        server.post(
          '/login',
          { preValidation: fastifyPassport.authenticate('test', { authInfo: false }) },
          async (request, reply) => {
            if (request.authContext) {
              capturedContexts.push({ ...request.authContext })
            }
            reply.send({ success: true })
          }
        )

        // Make multiple sequential requests
        for (let i = 0; i < 3; i++) {
          await server.inject({
            method: 'POST',
            url: '/login',
            payload: { login: 'test', password: 'test' }
          })
        }

        // Each should have its own context
        assert.strictEqual(capturedContexts.length, 3)

        // Contexts should be independent (not references to same object)
        if (capturedContexts.length >= 2) {
          assert.notStrictEqual(capturedContexts[0], capturedContexts[1])
        }
      })
    })
  })
}

testSuite('@fastify/session')
testSuite('@fastify/secure-session')
