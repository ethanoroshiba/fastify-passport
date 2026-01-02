import Fastify, { FastifyRequest, FastifyReply } from 'fastify'
import fastifySecureSession from '@fastify/secure-session'
import { Authenticator, AuthResult, Strategy } from './dist/index'
import type { AuthContext } from 'fastify'

/**
 * Example API Key Strategy - Checks for X-API-Key header
 * Simple validation: accepts keys starting with "valid-"
 */
class ApiKeyStrategy extends Strategy {
  constructor () {
    super('apikey')
  }

  async authenticate (request: FastifyRequest) {
    // Add small delay to demonstrate timing capture in AuthContext
    await new Promise(resolve => setTimeout(resolve, 15))

    const apiKey = request.headers['x-api-key'] as string | undefined

    if (!apiKey) {
      return this.fail('Missing API key', 401)
    }

    if (!apiKey.startsWith('valid-')) {
      return this.fail('Invalid API key format', 401)
    }

    const user = {
      id: `apikey-${apiKey}`,
      username: `user-${apiKey.substring(6)}`,
      authMethod: 'apikey'
    }

    this.success(user, { type: 'apikey', message: 'Authenticated via API key' })
  }
}

// Note: session strategy already exists, so we don't need to define it here

// ============================================================================
// Server Setup
// ============================================================================

const server = Fastify()

// Setup secure session for session-based auth
server.register(fastifySecureSession, {
  key: Buffer.from('a'.repeat(32)),
  cookie: {
    path: '/',
    httpOnly: true
  }
})

const passport = new Authenticator()
passport.use(new ApiKeyStrategy())

// User serialization for session
passport.registerUserSerializer(async (user: any) => {
  return { id: user.id, username: user.username, authMethod: user.authMethod }
})

passport.registerUserDeserializer(async (sessionUser: any) => {
  return sessionUser
})

server.register(passport.initialize())
server.register(passport.secureSession())

// ============================================================================
// Demo Endpoints
// ============================================================================

/**
 * DEMO 1: Conditional Authentication
 *
 * This endpoint demonstrates the power of programmatic authentication control.
 * It tries multiple strategies in sequence with custom fallback logic:
 * 1. First, check if user has an active session
 * 2. If no session, try API key authentication
 *
 * This showcases how authenticateRequest() allows applications to implement
 * sophisticated authentication flows than simply stopping at the first successful
 * strategy.
 */
server.get('/conditional-auth', async (request: FastifyRequest, reply: FastifyReply) => {
  const results: { strategy: string; result: AuthResult; attempted: boolean }[] = []
  let finalUser: any = null

  // Try Session first (if user is already logged in)
  const sessionResult = await passport.authenticateRequest('session', request, reply, { session: false })
  results.push({ strategy: 'session', result: sessionResult, attempted: true })

  if (sessionResult.ok) {
    finalUser = sessionResult.user
  } else {
    // Fallback to API Key
    const apiKeyResult = await passport.authenticateRequest('apikey', request, reply, { session: false })
    results.push({ strategy: 'apikey', result: apiKeyResult, attempted: true })

    if (apiKeyResult.ok) {
      finalUser = apiKeyResult.user
    }
  }

  if (finalUser) {
    return {
      message: 'Authentication successful via conditional fallback',
      user: finalUser,
      authenticationFlow: results.map(r => ({
        strategy: r.strategy,
        succeeded: r.result.ok,
        usedFor: r.result.ok ? 'AUTHENTICATED USER' : 'tried but failed'
      })),
      explanation: 'Multiple strategies were tried in sequence until one succeeded'
    }
  } else {
    reply.code(401)
    return {
      message: 'All authentication methods failed',
      attemptedStrategies: results.map(r => ({
        strategy: r.strategy,
        status: r.result.status,
        challenges: r.result.challenges
      })),
      hint: 'Try one of: session cookie or X-API-Key header (valid-*)'
    }
  }
})

/**
 * DEMO 2: Custom Error Handling
 *
 * This endpoint demonstrates how AuthResult provides rich contextual information
 * about authentication failures, allowing applications to provide better error
 * messages to clients instead of generic 401s.
 *
 * It attempts multiple strategies (session and API key) in a single call,
 * and AuthResult captures detailed information about all failed attempts.
 */
server.get('/custom-errors', async (request: FastifyRequest, reply: FastifyReply) => {
  const result = await passport.authenticateRequest(['session', 'apikey'], request, reply, { session: false })

  if (result.ok) {
    return {
      message: 'Authentication successful',
      user: result.user,
      strategy: result.strategy,
      info: result.info,
      note: 'Authenticated using one of multiple strategies'
    }
  } else {
    // Use AuthResult to provide rich, contextual error information
    // When multiple strategies fail, challenges array contains info from each
    const challenges = result.challenges || []

    reply.code(result.status || 401)

    return {
      error: 'Authentication Failed',
      message: 'All authentication strategies were attempted but none succeeded',
      attemptedStrategy: result.strategy,
      status: result.status,
      failureDetails: challenges.map((challenge, index) => {
        // Provide specific guidance for each failure type
        if (typeof challenge === 'string') {
          if (challenge.includes('Missing API key')) {
            return {
              strategy: 'apikey',
              issue: 'Missing API key',
              guidance: 'Provide X-API-Key header with value starting with "valid-"',
              example: 'X-API-Key: valid-test123'
            }
          } else if (challenge.includes('Invalid API key')) {
            return {
              strategy: 'apikey',
              issue: 'Invalid API key format',
              guidance: 'API key must start with "valid-"',
              example: 'valid-demo, valid-test123, valid-mykey'
            }
          } else {
            return {
              strategy: index === 0 ? 'session' : 'apikey',
              challenge: challenge as string
            }
          }
        }
        return challenge
      }),
      explanation: 'AuthResult captures detailed information about ALL attempted strategies, ' +
                   'allowing rich, actionable error messages instead of generic 401s.',
      hint: 'Provide either a valid session cookie or an API key starting with "valid-"'
    }
  }
})

/**
 * DEMO 3: Observability
 *
 * This endpoint demonstrates how AuthContext captures timing and strategy
 * information for observability purposes. This is useful for:
 * - Monitoring authentication performance
 * - Debugging authentication issues
 * - Security auditing
 * - Understanding user authentication patterns
 *
 * The endpoint tries multiple strategies in a single call, and AuthContext
 * captures detailed timing information for each strategy attempt.
 */
server.get('/observability', async (request: FastifyRequest, reply: FastifyReply) => {
  // Initialize authContext to enable tracking
  const authContext: AuthContext = {
    attemptedStrategies: [],
    elapsedMs: 0,
    status: 'rejected',
    elapsedPerStrategy: [],
    userId: '',
    requestedScope: ''
  }
  request.authContext = authContext

  // Try multiple strategies - AuthContext will capture timing for each
  const result = await passport.authenticateRequest(['session', 'apikey'], request, reply, { session: false })

  // AuthContext is now populated with timing and strategy information
  if (result.ok) {
    return {
      message: 'Authentication successful with observability',
      user: result.user,
      successfulStrategy: result.strategy,
      observability: {
        authContext: request.authContext,
        interpretation: {
          strategiesAttempted: request.authContext?.attemptedStrategies.length,
          totalTimeMs: request.authContext?.elapsedMs,
          perStrategyTiming: request.authContext?.elapsedPerStrategy,
          finalStatus: request.authContext?.status,
          note: 'Each strategy attempt is timed individually, useful for identifying slow auth methods'
        }
      },
      explanation: 'AuthContext provides detailed timing and strategy information for monitoring and debugging. ' +
                   'This data can be logged for security auditing or used to optimize authentication performance.'
    }
  } else {
    reply.code(401)
    return {
      error: 'Authentication failed',
      observability: {
        authContext: request.authContext,
        interpretation: {
          strategiesAttempted: request.authContext?.attemptedStrategies.length,
          totalTimeMs: request.authContext?.elapsedMs,
          perStrategyTiming: request.authContext?.elapsedPerStrategy,
          finalStatus: request.authContext?.status,
          note: 'Even on failure, timing data shows how long each strategy took before rejecting'
        }
      },
      explanation: 'Even on failure, AuthContext captures valuable information about the authentication attempt.',
      hint: 'Provide valid credentials using X-API-Key header (starting with "valid-")'
    }
  }
})

// ============================================================================
// Automated Demo Tests
// ============================================================================

/**
 * Runs automated tests to demonstrate the new features
 */
async function runDemoTests () {
  console.log('')
  console.log('═══════════════════════════════════════════════════════════')
  console.log('  Running Automated Demo Tests')
  console.log('═══════════════════════════════════════════════════════════')
  console.log('')

  const baseUrl = 'http://localhost:3000'

  // Helper to make requests and display results
  const testRequest = async (name: string, description: string, options: RequestInit & { url: string }) => {
    console.log(`\n📋 Test: ${name}`)
    console.log(`   ${description}`)
    console.log(`   Request: ${options.method || 'GET'} ${options.url}`)

    if (options.headers) {
      const headers = options.headers as Record<string, string>
      Object.entries(headers).forEach(([key, value]) => {
        console.log(`   Header: ${key}: ${value}`)
      })
    }

    try {
      const response = await fetch(options.url, options)
      const data = await response.json()

      console.log(`   Status: ${response.status}`)
      console.log('   Response:')
      console.log(JSON.stringify(data, null, 2).split('\n').map(line => `     ${line}`).join('\n'))

      return { success: response.ok, data }
    } catch (err) {
      console.log(`   ❌ Error: ${err}`)
      return { success: false, data: null }
    }
  }

  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')
  console.log('DEMO 1: Conditional Authentication')
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')
  console.log('This demonstrates programmatic control over authentication')
  console.log('with multiple strategy fallbacks using authenticateRequest()')

  await testRequest(
    'API Key Authentication Success',
    'Session fails, API key succeeds - stops fallback chain',
    {
      url: `${baseUrl}/conditional-auth`,
      method: 'GET',
      headers: { 'X-API-Key': 'valid-test123' }
    }
  )

  await testRequest(
    'All Strategies Fail',
    'Shows both strategies attempted and their failures',
    {
      url: `${baseUrl}/conditional-auth`,
      method: 'GET'
    }
  )

  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')
  console.log('DEMO 2: Custom Error Handling')
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')
  console.log('This demonstrates rich error messages using AuthResult context')
  console.log('Multiple strategies are attempted in a single authenticateRequest call')

  await testRequest(
    'Multiple Strategies Fail',
    'Shows detailed context from both session and API key failures',
    {
      url: `${baseUrl}/custom-errors`,
      method: 'GET'
    }
  )

  await testRequest(
    'Multiple Strategies - API Key Succeeds',
    'Session fails but API key succeeds, showing which strategy worked',
    {
      url: `${baseUrl}/custom-errors`,
      method: 'GET',
      headers: { 'X-API-Key': 'valid-demo' }
    }
  )

  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')
  console.log('DEMO 3: Observability')
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━')
  console.log('This demonstrates AuthContext capturing timing and strategy info')
  console.log('Multiple strategies are attempted and per-strategy timing is captured')

  await testRequest(
    'Successful Authentication with Per-Strategy Metrics',
    'Captures timing for each strategy - session fails, apikey succeeds',
    {
      url: `${baseUrl}/observability`,
      method: 'GET',
      headers: { 'X-API-Key': 'valid-demo' }
    }
  )

  await testRequest(
    'Failed Authentication with Per-Strategy Metrics',
    'Captures timing for both strategies even when all fail',
    {
      url: `${baseUrl}/observability`,
      method: 'GET'
    }
  )

  console.log('')
  console.log('═══════════════════════════════════════════════════════════')
  console.log('  Demo Tests Complete!')
  console.log('═══════════════════════════════════════════════════════════')
  console.log('')
  console.log('To run the server interactively for manual testing, start it with:')
  console.log('  npx tsx demo-auth-server.ts')
  console.log('')
  console.log('Shutting down demo server...')
  console.log('')
}

// ============================================================================
// Start Server
// ============================================================================

const start = async () => {
  try {
    await server.listen({ port: 3000, host: '0.0.0.0' })

    console.log('')
    console.log('═══════════════════════════════════════════════════════════')
    console.log('  FastifyPassport Demo Server')
    console.log('═══════════════════════════════════════════════════════════')
    console.log('')
    console.log('Server started at: http://localhost:3000')
    console.log('')

    // Run automated tests
    await new Promise(resolve => setTimeout(resolve, 500)) // Wait for server to be ready
    await runDemoTests()

    // Gracefully shutdown the server after demo
    await new Promise(resolve => setTimeout(resolve, 1000)) // Give user time to read final message
    await server.close()
    console.log('Demo complete!')
    process.exit(0)
  } catch (err) {
    console.error('Failed to start server:', err)
    process.exit(1)
  }
}

start()
