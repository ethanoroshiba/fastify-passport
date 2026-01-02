import assert from 'node:assert'
import { describe, test } from 'node:test'
import '../src/index'
import { getConfiguredTestServer, TestStrategy } from './helpers'

const testSuite = (sessionPluginName: string) => {
  describe(`${sessionPluginName} tests`, () => {
    const sessionOnlyTest = sessionPluginName === '@fastify/session' ? test : test.skip
    const secureSessionOnlyTest = sessionPluginName === '@fastify/secure-session' ? test : test.skip

    describe('Request decorators', () => {
      test('logIn allows logging in an arbitrary user', async () => {
        const { server, fastifyPassport } = getConfiguredTestServer()
        server.get(
          '/',
          { preValidation: fastifyPassport.authenticate('test', { authInfo: false }) },
          async (request) => (request.user as any).name
        )
        server.post('/force-login', async (request, reply) => {
          await request.logIn({ name: 'force logged in user' })
          reply.send('logged in')
        })

        const login = await server.inject({
          method: 'POST',
          url: '/force-login'
        })

        assert.strictEqual(login.statusCode, 200)

        const response = await server.inject({
          url: '/',
          headers: {
            cookie: login.headers['set-cookie']
          },
          method: 'GET'
        })

        assert.strictEqual(login.statusCode, 200)
        assert.strictEqual(response.body, 'force logged in user')
      })

      secureSessionOnlyTest(
        'logIn allows logging in an arbitrary user for the duration of the request if session=false',
        async () => {
          const { server } = getConfiguredTestServer()
          server.post('/force-login', async (request, reply) => {
            await request.logIn({ name: 'force logged in user' }, { session: false })
            reply.send((request.user as any).name)
          })

          const login = await server.inject({
            method: 'POST',
            url: '/force-login'
          })

          assert.strictEqual(login.statusCode, 200)
          assert.strictEqual(login.body, 'force logged in user')
          assert.strictEqual(login.headers['set-cookie'], undefined) // no user added to session
        }
      )

      sessionOnlyTest(
        'logIn allows logging in an arbitrary user for the duration of the request if session=false',
        async () => {
          const sessionOptions = {
            secret: 'a secret with minimum length of 32 characters',
            cookie: { secure: false },
            saveUninitialized: false
          }
          const { server } = getConfiguredTestServer('test', new TestStrategy('test'), sessionOptions)
          server.post('/force-login', async (request, reply) => {
            await request.logIn({ name: 'force logged in user' }, { session: false })
            reply.send((request.user as any).name)
          })

          const login = await server.inject({
            method: 'POST',
            url: '/force-login'
          })

          assert.strictEqual(login.statusCode, 200)
          assert.strictEqual(login.body, 'force logged in user')
          assert.strictEqual(login.headers['set-cookie'], undefined) // no user added to session
        }
      )

      test('isUnauthenticated returns true when user is not authenticated', async () => {
        const { server } = getConfiguredTestServer()
        server.get('/check-auth', async (request, reply) => {
          reply.send({ isUnauthenticated: request.isUnauthenticated() })
        })

        const response = await server.inject({
          method: 'GET',
          url: '/check-auth'
        })

        assert.strictEqual(response.statusCode, 200)
        const body = response.json()
        assert.strictEqual(body.isUnauthenticated, true)
      })

      test('isUnauthenticated returns false when user is authenticated', async () => {
        const { server } = getConfiguredTestServer()
        server.post('/login', async (request, reply) => {
          await request.logIn({ name: 'test user' })
          reply.send({ isUnauthenticated: request.isUnauthenticated() })
        })

        const response = await server.inject({
          method: 'POST',
          url: '/login'
        })

        assert.strictEqual(response.statusCode, 200)
        const body = response.json()
        assert.strictEqual(body.isUnauthenticated, false)
      })

      test('should logout', async () => {
        const { server, fastifyPassport } = getConfiguredTestServer()
        server.get(
          '/',
          { preValidation: fastifyPassport.authenticate('test', { authInfo: false }) },
          async () => 'the root!'
        )
        server.get(
          '/logout',
          { preValidation: fastifyPassport.authenticate('test', { authInfo: false }) },
          async (request, reply) => {
            request.logout()
            reply.send('logged out')
          }
        )
        server.post(
          '/login',
          { preValidation: fastifyPassport.authenticate('test', { successRedirect: '/', authInfo: false }) },
          async () => ''
        )

        const login = await server.inject({
          method: 'POST',
          payload: { login: 'test', password: 'test' },
          url: '/login'
        })
        assert.strictEqual(login.statusCode, 302)
        assert.strictEqual(login.headers.location, '/')

        const logout = await server.inject({
          url: '/logout',
          headers: {
            cookie: login.headers['set-cookie']
          },
          method: 'GET'
        })

        assert.strictEqual(logout.statusCode, 200)
        assert.ok(logout.headers['set-cookie'])

        const retry = await server.inject({
          url: '/',
          headers: {
            cookie: logout.headers['set-cookie']
          },
          method: 'GET'
        })

        assert.strictEqual(retry.statusCode, 401)
      })

      test('authContext can be set on request', async () => {
        const { server } = getConfiguredTestServer()
        server.get('/test-context', async (request, reply) => {
          request.authContext = {
            attemptedStrategies: ['test'],
            elapsedMs: 100,
            status: 'authenticated',
            userId: 'user123'
          }
          reply.send(request.authContext)
        })

        const response = await server.inject({
          method: 'GET',
          url: '/test-context'
        })

        assert.strictEqual(response.statusCode, 200)
        const body = response.json()
        assert.strictEqual(body.attemptedStrategies[0], 'test')
        assert.strictEqual(body.elapsedMs, 100)
        assert.strictEqual(body.status, 'authenticated')
        assert.strictEqual(body.userId, 'user123')
      })

      test('authContext should be independent per request', async () => {
        const { server } = getConfiguredTestServer()
        let requestCount = 0

        server.get('/independent', async (request, reply) => {
          const currentRequest = ++requestCount
          request.authContext = {
            attemptedStrategies: [`strategy-${currentRequest}`],
            elapsedMs: currentRequest * 10,
            status: 'authenticated',
            userId: `user-${currentRequest}`
          }
          // Simulate async work
          await new Promise(resolve => setTimeout(resolve, 10))
          reply.send(request.authContext)
        })

        // Make concurrent requests
        const [response1, response2, response3] = await Promise.all([
          server.inject({ method: 'GET', url: '/independent' }),
          server.inject({ method: 'GET', url: '/independent' }),
          server.inject({ method: 'GET', url: '/independent' })
        ])

        const body1 = response1.json()
        const body2 = response2.json()
        const body3 = response3.json()

        // Collect all strategy names from the three responses
        const strategyNames = new Set([
          body1.attemptedStrategies[0],
          body2.attemptedStrategies[0],
          body3.attemptedStrategies[0]
        ])

        // All three should be unique (no context bleed between requests)
        assert.strictEqual(strategyNames.size, 3, 'All three requests should have unique contexts')

        // Verify they match the expected set
        assert.ok(strategyNames.has('strategy-1'))
        assert.ok(strategyNames.has('strategy-2'))
        assert.ok(strategyNames.has('strategy-3'))

        // User IDs should also all be different
        const userIds = new Set([body1.userId, body2.userId, body3.userId])
        assert.strictEqual(userIds.size, 3, 'All three requests should have unique user IDs')
      })
    })
  })
}

testSuite('@fastify/session')
testSuite('@fastify/secure-session')

testSuite('@fastify/session')
testSuite('@fastify/secure-session')
