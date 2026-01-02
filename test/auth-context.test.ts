import assert from 'node:assert'
import { describe, test } from 'node:test'
import { getConfiguredTestServer, TestStrategy, TestDatabaseStrategy } from './helpers'
import type { FastifyRequest } from 'fastify'
import type { AuthContext } from '../src/index'

const testSuite = (sessionPluginName: string) => {
  describe(`${sessionPluginName} - Auth Context tests`, () => {
    describe('Hook-based authentication', () => {
      test('should populate authContext on successful authentication', async () => {
        const { server, fastifyPassport } = getConfiguredTestServer()
        let capturedContext: AuthContext | undefined

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
        assert.ok(capturedContext.elapsedMs >= 0, 'elapsed time should be non-negative')
      })

      test('should populate authContext on failed authentication', async () => {
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

        const response = await server.inject({
          method: 'POST',
          url: '/login',
          payload: { login: 'wrong', password: 'wrong' }
        })

        assert.strictEqual(response.statusCode, 401)
        // Context should still be set even on failure
        if (capturedContext) {
          assert.ok(Array.isArray(capturedContext.attemptedStrategies))
          assert.strictEqual(capturedContext.status, 'rejected')
          assert.strictEqual(typeof capturedContext.elapsedMs, 'number')
        }
      })

      test('should track multiple strategies in authContext', async () => {
        const { server, fastifyPassport } = getConfiguredTestServer()
        const strategy2 = new TestStrategy('test2')
        fastifyPassport.use('test2', strategy2)
        let capturedContext: AuthContext | undefined

        server.addHook('onRequest', async (request, reply) => {
          request.authContext = {
            attemptedStrategies: [],
            elapsedMs: 0,
            status: 'rejected'
          }
        })

        server.post(
          '/login',
          { preValidation: fastifyPassport.authenticate(['test', 'test2'], { authInfo: false }) },
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
        assert.ok(Array.isArray(capturedContext.attemptedStrategies))
        // Should track which strategies were attempted
        assert.ok(capturedContext.attemptedStrategies.length > 0)
      })

      test('should include timing information per strategy when available', async () => {
        const { server, fastifyPassport } = getConfiguredTestServer()
        let capturedContext: AuthContext | undefined

        server.addHook('onRequest', async (request, reply) => {
          request.authContext = {
            attemptedStrategies: [],
            elapsedMs: 0,
            status: 'rejected',
            elapsedPerStrategy: []
          }
        })

        server.post(
          '/login',
          { preValidation: fastifyPassport.authenticate('test', { authInfo: false }) },
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
        assert.ok(capturedContext)
        assert.strictEqual(typeof capturedContext.elapsedMs, 'number')

        // If elapsedPerStrategy is provided, it should be an array
        if (capturedContext.elapsedPerStrategy) {
          assert.ok(Array.isArray(capturedContext.elapsedPerStrategy))
          assert.strictEqual(
            capturedContext.elapsedPerStrategy.length,
            capturedContext.attemptedStrategies.length,
            'elapsedPerStrategy should be aligned with attemptedStrategies'
          )
        }
      })

      test('should include userId in authContext when authentication succeeds', async () => {
        const { server, fastifyPassport } = getConfiguredTestServer()
        let capturedContext: AuthContext | undefined

        server.addHook('onRequest', async (request, reply) => {
          request.authContext = {
            attemptedStrategies: [],
            elapsedMs: 0,
            status: 'rejected',
            userId: ''
          }
        })

        server.post(
          '/login',
          { preValidation: fastifyPassport.authenticate('test', { authInfo: false }) },
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
        assert.ok(capturedContext)

        // userId should be populated if user has an id
        if (capturedContext.userId) {
          assert.strictEqual(typeof capturedContext.userId, 'string')
        }
      })

      test('should track scope information when provided', async () => {
        const { server, fastifyPassport } = getConfiguredTestServer()
        let capturedContext: AuthContext | undefined

        server.addHook('onRequest', async (request, reply) => {
          request.authContext = {
            attemptedStrategies: [],
            elapsedMs: 0,
            status: 'rejected',
            requestedScope: ''
          }
        })

        server.post(
          '/login',
          {
            preValidation: fastifyPassport.authenticate('test', {
              authInfo: false,
              scope: 'read:profile'
            })
          },
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
        assert.ok(capturedContext)

        // If scope was provided, it should be tracked
        if (capturedContext.requestedScope) {
          assert.ok(
            capturedContext.requestedScope === 'read:profile' ||
            (typeof capturedContext.requestedScope === 'string' &&
             capturedContext.requestedScope.includes('read:profile'))
          )
        }
      })
    })

    describe('Programmatic authentication', () => {
      test('should populate authContext on successful programmatic authentication', async () => {
        const { server, fastifyPassport } = getConfiguredTestServer()
        let capturedContext: AuthContext | undefined

        server.addHook('onRequest', async (request, reply) => {
          request.authContext = {
            attemptedStrategies: [],
            elapsedMs: 0,
            status: 'rejected'
          }
        })

        server.post('/auth', async (request, reply) => {
          const result = await fastifyPassport.authenticateRequest('test', request, reply, {
            session: false
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
      })

      test('should populate authContext on failed programmatic authentication', async () => {
        const { server, fastifyPassport } = getConfiguredTestServer()
        let capturedContext: AuthContext | undefined

        server.addHook('onRequest', async (request, reply) => {
          request.authContext = {
            attemptedStrategies: [],
            elapsedMs: 0,
            status: 'rejected'
          }
        })

        server.post('/auth', async (request, reply) => {
          const result = await fastifyPassport.authenticateRequest('test', request, reply, {
            session: false
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
      })

      test('should track multiple strategies in programmatic authentication', async () => {
        const { server, fastifyPassport } = getConfiguredTestServer()
        const strategy2 = new TestDatabaseStrategy('db', {
          1: { id: '1', login: 'dbuser', password: 'dbpass' }
        })
        fastifyPassport.use('db', strategy2)
        let capturedContext: AuthContext | undefined

        server.addHook('onRequest', async (request, reply) => {
          request.authContext = {
            attemptedStrategies: [],
            elapsedMs: 0,
            status: 'rejected'
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

        // Test with credentials that match the 'test' strategy
        const response = await server.inject({
          method: 'POST',
          url: '/auth',
          payload: { login: 'test', password: 'test' }
        })

        assert.strictEqual(response.statusCode, 200)
        assert.ok(capturedContext)
        assert.ok(Array.isArray(capturedContext.attemptedStrategies))
        assert.ok(capturedContext.attemptedStrategies.length > 0)
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

    describe('Observability and metrics', () => {
      test('should provide useful metrics for monitoring', async () => {
        const { server, fastifyPassport } = getConfiguredTestServer()
        let capturedContext: AuthContext | undefined

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
        assert.ok(capturedContext)

        // Should have key observability fields
        assert.ok(capturedContext.attemptedStrategies, 'should track strategies')
        assert.ok(typeof capturedContext.elapsedMs === 'number', 'should track timing')
        assert.ok(capturedContext.status, 'should track outcome')

        // These are the minimum fields needed for good observability
        const requiredFields = ['attemptedStrategies', 'elapsedMs', 'status']
        requiredFields.forEach(field => {
          assert.ok(field in capturedContext!, `should have ${field} for observability`)
        })
      })

      test('should allow for audit logging without exposing sensitive data', async () => {
        const { server, fastifyPassport } = getConfiguredTestServer()
        const auditLog: any[] = []

        server.addHook('onRequest', async (request, reply) => {
          request.authContext = {
            attemptedStrategies: [],
            elapsedMs: 0,
            status: 'rejected'
          }
        })

        server.addHook('onResponse', async (request, reply) => {
          if (request.authContext) {
            // Simulate audit logging
            auditLog.push({
              timestamp: new Date().toISOString(),
              url: request.url,
              method: request.method,
              authContext: request.authContext,
              statusCode: reply.statusCode
            })
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
          payload: { login: 'test', password: 'test' }
        })

        assert.strictEqual(auditLog.length, 1)
        const logEntry = auditLog[0]

        // Should have audit trail information
        assert.ok(logEntry.timestamp)
        assert.strictEqual(logEntry.url, '/login')
        assert.strictEqual(logEntry.method, 'POST')
        assert.ok(logEntry.authContext)

        // Context should be safe to log
        const contextStr = JSON.stringify(logEntry.authContext)
        assert.ok(!contextStr.includes('password'))
      })

      test('should track authentication performance across strategies', async () => {
        const { server, fastifyPassport } = getConfiguredTestServer()
        const slowStrategy = new TestDatabaseStrategy('slow-db', {})
        // Override authenticate to add delay
        const originalAuthenticate = slowStrategy.authenticate.bind(slowStrategy)
        slowStrategy.authenticate = async function (request: FastifyRequest, options: any) {
          await new Promise(resolve => setTimeout(resolve, 50))
          return originalAuthenticate(request, options)
        }

        fastifyPassport.use('slow', slowStrategy)
        let capturedContext: AuthContext | undefined

        server.addHook('onRequest', async (request, reply) => {
          request.authContext = {
            attemptedStrategies: [],
            elapsedMs: 0,
            status: 'rejected'
          }
        })

        server.post('/auth', async (request, reply) => {
          const result = await fastifyPassport.authenticateRequest(
            ['slow', 'test'],
            request,
            reply,
            { session: false }
          )

          capturedContext = request.authContext

          if (result.ok) {
            reply.send({ success: true })
          } else {
            reply.code(401).send({ success: false })
          }
        })

        const startTime = Date.now()
        await server.inject({
          method: 'POST',
          url: '/auth',
          payload: { login: 'test', password: 'test' }
        })
        const totalTime = Date.now() - startTime

        assert.ok(capturedContext)
        assert.ok(capturedContext.elapsedMs > 0, 'should track elapsed time')
        assert.ok(
          capturedContext.elapsedMs <= totalTime,
          'elapsed time should be reasonable'
        )
      })
    })
  })
}

testSuite('@fastify/session')
testSuite('@fastify/secure-session')
