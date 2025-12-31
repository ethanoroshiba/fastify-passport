import type { FastifyPluginAsync, FastifyReply, FastifyRequest, PassportUser, RouteHandlerMethod } from 'fastify'
import { fastifyPlugin } from 'fastify-plugin'
import { type AuthenticateCallback, type AuthenticateOptions, AuthenticationRoute, FailureObject, StrategyError } from './AuthenticationRoute'
import { CreateInitializePlugin } from './CreateInitializePlugin'
import { SecureSessionManager } from './session-managers/SecureSessionManager'
import type { AnyStrategy } from './strategies/index'
import type { Strategy } from './strategies/base'
import { SessionStrategy } from './strategies/SessionStrategy'

export type SerializeFunction<User = any, SerializedUser = any> = (
  user: User,
  req: FastifyRequest
) => Promise<SerializedUser>

export type DeserializeFunction<SerializedUser = any, User = any> = (
  serialized: SerializedUser,
  req: FastifyRequest
) => Promise<User>

export type InfoTransformerFunction = (info: any) => Promise<any>

export interface AuthenticatorOptions {
  key?: string
  userProperty?: string
  clearSessionOnLogin?: boolean
  clearSessionIgnoreFields?: string[]
}



export interface AuthResult {
  ok: boolean
  strategy: string
  user?: PassportUser
  info?: { type?: string; message?: string }
  status?: 401 | 403
  error?: Error
  challenges?: string[]
}

export class Authenticator {
  // a Fastify-instance wide unique string identifying this instance of fastify-passport (default: "passport")
  public key: string
  // the key on the request at which to store the deserialized user value (default: "user")
  public userProperty: string
  public sessionManager: SecureSessionManager

  private strategies: { [k: string]: AnyStrategy } = {}
  private serializers: SerializeFunction<any, any>[] = []
  private deserializers: DeserializeFunction<any, any>[] = []
  private infoTransformers: InfoTransformerFunction[] = []
  private clearSessionOnLogin: boolean
  private clearSessionIgnoreFields: string[]

  constructor(options: AuthenticatorOptions = {}) {
    this.key = options.key || 'passport'
    this.userProperty = options.userProperty || 'user'
    this.use(new SessionStrategy(this.deserializeUser.bind(this)))
    this.clearSessionOnLogin = options.clearSessionOnLogin ?? true
    this.clearSessionIgnoreFields = ['passport', 'session', ...(options.clearSessionIgnoreFields || [])]
    this.sessionManager = new SecureSessionManager(
      {
        key: this.key,
        clearSessionOnLogin: this.clearSessionOnLogin,
        clearSessionIgnoreFields: this.clearSessionIgnoreFields
      },
      this.serializeUser.bind(this)
    )
  }

  use(strategy: AnyStrategy): this
  use(name: string, strategy: AnyStrategy): this
  use(name: AnyStrategy | string, strategy?: AnyStrategy): this {
    if (!strategy) {
      strategy = name as AnyStrategy
      name = strategy.name as string
    }
    if (!name) {
      throw new Error('Authentication strategies must have a name')
    }

    this.strategies[name as string] = strategy
    return this
  }

  public unuse(name: string): this {
    delete this.strategies[name]
    return this
  }

  public initialize(): FastifyPluginAsync {
    return CreateInitializePlugin(this)
  }

  /**
   * Authenticates requests.
   *
   * Applies the `name`ed strategy (or strategies) to the incoming request, in order to authenticate the request.  If authentication is successful, the user will be logged in and populated at `req.user` and a session will be established by default.  If authentication fails, an unauthorized response will be sent.
   *
   * Options:
   *   - `session`          Save login state in session, defaults to _true_
   *   - `successRedirect`  After successful login, redirect to given URL
   *   - `successMessage`   True to store success message in
   *                        req.session.messages, or a string to use as override
   *                        message for success.
   *   - `successFlash`     True to flash success messages or a string to use as a flash
   *                        message for success (overrides any from the strategy itself).
   *   - `failureRedirect`  After failed login, redirect to given URL
   *   - `failureMessage`   True to store failure message in
   *                        req.session.messages, or a string to use as override
   *                        message for failure.
   *   - `failureFlash`     True to flash failure messages or a string to use as a flash
   *                        message for failures (overrides any from the strategy itself).
   *   - `assignProperty`   Assign the object provided by the verify callback to given property
   *
   * An optional `callback` can be supplied to allow the application to override the default manner in which authentication attempts are handled.  The callback has the following signature, where `user` will be set to the authenticated user on a successful authentication attempt, or `false` otherwise.  An optional `info` argument will be passed, containing additional details provided by the strategy's verify callback - this could be information about a successful authentication or a challenge message for a failed authentication. An optional `status` argument will be passed when authentication fails - this could be a HTTP response code for a remote authentication failure or similar.
   *
   *     fastify.get('/protected', function(req, res, next) {
   *       passport.authenticate('local', function(err, user, info, status) {
   *         if (err) { return next(err) }
   *         if (!user) { return res.redirect('/signin') }
   *         res.redirect('/account');
   *       })(req, res, next);
   *     });
   *
   * Note that if a callback is supplied, it becomes the application's responsibility to log-in the user, establish a session, and otherwise perform the desired operations.
   *
   * Examples:
   *
   *    // protect a route with a validation handler
   *    fastify.get(
   *      '/protected',
   *      { preValidation: fastifyPassport.authenticate('local', {failureRedirect: '/login}) },
   *      async (request, reply) => {
   *       reply.send("Hello " + request.user.name);
   *      }
   *    )
   *
   *    // handle a route with a custom callback that uses request/reply to handle the request depending on the authentication result
   *    fastify.get('/checkLogin', fastifyPassport.authenticate('local', async (request, reply, err, user) => {
   *      if (user) {
   *        return reply.redirect(request.session.get('returnTo'));
   *      } else {
   *        return reply.redirect('/login');
   *      }
        })
   *
   *    fastifyPassport.authenticate('basic', { session: false })(req, res);
   *
   *    fastify.get('/auth/twitter', fastifyPassport.authenticate('twitter'));
   *    fastify.get('/auth/twitter/callback', fastifyPassport.authenticate('twitter', { successRedirect: '/', failureRedirect: '/login' }))
   *
   * @param {|String|Array} name
   * @param {Object} options
   * @param {Function} callback
   * @return {Function}
   * @api public
   */

  public authenticate<StrategyOrStrategies extends string | Strategy | (string | Strategy)[]>(
    strategy: StrategyOrStrategies,
    callback?: AuthenticateCallback<StrategyOrStrategies>
  ): RouteHandlerMethod
  public authenticate<StrategyOrStrategies extends string | Strategy | (string | Strategy)[]>(
    strategy: StrategyOrStrategies,
    options?: AuthenticateOptions
  ): RouteHandlerMethod
  public authenticate<StrategyOrStrategies extends string | Strategy | (string | Strategy)[]>(
    strategy: StrategyOrStrategies,
    options?: AuthenticateOptions,
    callback?: AuthenticateCallback<StrategyOrStrategies>
  ): RouteHandlerMethod
  public authenticate<StrategyOrStrategies extends string | Strategy | (string | Strategy)[]>(
    strategyOrStrategies: StrategyOrStrategies,
    optionsOrCallback?: AuthenticateOptions | AuthenticateCallback<StrategyOrStrategies>,
    callback?: AuthenticateCallback<StrategyOrStrategies>
  ): RouteHandlerMethod {
    let options: AuthenticateOptions | undefined
    if (typeof optionsOrCallback === 'function') {
      options = {}
      callback = optionsOrCallback
    } else {
      options = optionsOrCallback
    }

    return new AuthenticationRoute(this, strategyOrStrategies, options, callback).handler
  }

  /**
   * Authenticates requests programmatically.
   *
   * Applies the `name`ed strategy (or strategies) to the incoming request, in order to authenticate the request.  If authentication is successful, the user will be logged in and populated at `req.user` and a session will be established by default.  If authentication fails, an AuthResult object with ok: false will be returned.
   *
   * Options:
   *   - `session`          Save login state in session, defaults to _true_
   *   - `successRedirect`  After successful login, redirect to given URL
   *   - `successMessage`   True to store success message in
   *                        req.session.messages, or a string to use as override
   *                        message for success.
   *   - `successFlash`     True to flash success messages or a string to use as a flash
   *                        message for success (overrides any from the strategy itself).
   *   - `failureRedirect`  After failed login, redirect to given URL
   *   - `failureMessage`   True to store failure message in
   *                        req.session.messages, or a string to use as override
   *                        message for failure.
   *   - `failureFlash`     True to flash failure messages or a string to use as a flash
   *                        message for failures (overrides any from the strategy itself).
   *   - `assignProperty`   Assign the object provided by the verify callback to given property
   *
   * This method returns a Promise that resolves to an AuthResult object, giving the application full control over how to handle authentication results. The AuthResult contains information about whether authentication succeeded, which strategy was used, the authenticated user, and any failure information.
   *
   * Examples:
   *
   *    // programmatically authenticate a request and handle the result
   *    const result = await fastifyPassport.authenticateRequest('local', request, reply, { session: false });
   *    if (result.ok) {
   *      reply.send({ user: result.user });
   *    } else {
   *      reply.code(result.status || 401).send({ error: result.challenges });
   *    }
   *
   *    // authenticate with session support
   *    const result = await fastifyPassport.authenticateRequest('jwt', request, reply);
   *    if (result.ok) {
   *      reply.redirect('/dashboard');
   *    } else {
   *      reply.redirect('/login');
   *    }
   *
   * @param {|String|Array} strategyOrStrategies
   * @param {FastifyRequest} request
   * @param {FastifyReply} reply
   * @param {Object} options
   * @return {Promise<AuthResult>}
   * @api public
   */
  public async authenticateRequest<StrategyOrStrategies extends string | Strategy | (string | Strategy)[]>(
    strategyOrStrategies: StrategyOrStrategies,
    request: FastifyRequest,
    reply: FastifyReply,
    options?: AuthenticateOptions
  ): Promise<AuthResult> {
    const authenticationRoute = new AuthenticationRoute(this, strategyOrStrategies, options)
      
    let failures: FailureObject[] = []
    let latestStrategy: string = 'unknown'
    let successInfo: { type?: string; message?: string } | undefined
    try {
      [failures, latestStrategy, successInfo] = await authenticationRoute.executeStrategies(request, reply)
    } catch (e) {
      // For other errors (strategy internal errors), sanitize and return them with the strategy name if available
      const errorMessage = (e as Error).message
      const sanitizedMessage = errorMessage ? sanitize(errorMessage) : 'Authentication error'
      return {
        ok: false,
        strategy: (e as StrategyError).strategy,
        status: 401,
        error: new Error(sanitizedMessage) // only include message to avoid leaking stack trace
      }
    }

    if (successInfo) {
      return {
        ok: true,
        strategy: latestStrategy,
        user: request.user,
        info: successInfo,
      }
    }

    // Sanitize all failure challenges before returning
    const sanitizedChallenges = failures.map(failure => {
      if (typeof failure.challenge === 'string') {
        return sanitize(failure.challenge)
      } else if (failure.challenge && typeof failure.challenge === 'object' && failure.challenge.message) {
        return sanitize(failure.challenge.message)
      }
      return failure.challenge
    })

    // If not explicit success info, treat as failure to catch case of all passes
    return {
      ok: false,
      strategy: latestStrategy,
      status: failures.length > 0 ? failures[0].status as 401 | 403 : 401, // default to 401 Unauthorized
      challenges: sanitizedChallenges as string[]
    }
  }

  /**
   * Hook or handler that will authorize a third-party account using the given `strategy` name, with optional `options`.
   *
   * If authorization is successful, the result provided by the strategy's verify callback will be assigned to `request.account`.  The existing login session and `request.user` will be unaffected.
   *
   * This function is particularly useful when connecting third-party accounts to the local account of a user that is currently authenticated.
   *
   * Examples:
   *
   *    passport.authorize('twitter-authz', { failureRedirect: '/account' });
   *
   * @param {String} strategy
   * @param {Object} options
   * @return {Function} middleware
   * @api public
   */

  public authorize<StrategyOrStrategies extends string | Strategy | (string | Strategy)[]>(
    strategy: StrategyOrStrategies,
    callback?: AuthenticateCallback<StrategyOrStrategies>
  ): RouteHandlerMethod
  public authorize<StrategyOrStrategies extends string | Strategy | (string | Strategy)[]>(
    strategy: StrategyOrStrategies,
    options?: AuthenticateOptions
  ): RouteHandlerMethod
  public authorize<StrategyOrStrategies extends string | Strategy | (string | Strategy)[]>(
    strategy: StrategyOrStrategies,
    options?: AuthenticateOptions,
    callback?: AuthenticateCallback<StrategyOrStrategies>
  ): RouteHandlerMethod
  public authorize<StrategyOrStrategies extends string | Strategy | (string | Strategy)[]>(
    strategyOrStrategies: StrategyOrStrategies,
    optionsOrCallback?: AuthenticateOptions | AuthenticateCallback<StrategyOrStrategies>,
    callback?: AuthenticateCallback<StrategyOrStrategies>
  ): RouteHandlerMethod {
    let options: AuthenticateOptions | undefined
    if (typeof optionsOrCallback === 'function') {
      options = {}
      callback = optionsOrCallback
    } else {
      options = optionsOrCallback
    }
    options || (options = {})
    options.assignProperty = 'account'

    return new AuthenticationRoute(this, strategyOrStrategies, options, callback).handler
  }

  /**
   * Hook or handler that will restore login state from a session managed by @fastify/secure-session.
   *
   * Web applications typically use sessions to maintain login state between requests.  For example, a user will authenticate by entering credentials into a form which is submitted to the server.  If the credentials are valid, a login session is established by setting a cookie containing a session identifier in the user's web browser.  The web browser will send this cookie in subsequent requests to the server, allowing a session to be maintained.
   *
   * If sessions are being utilized, and a login session has been established, this middleware will populate `request.user` with the current user.
   *
   * Note that sessions are not strictly required for Passport to operate. However, as a general rule, most web applications will make use of sessions. An exception to this rule would be an API server, which expects each HTTP request to provide credentials in an Authorization header.
   *
   * Examples:
   *
   *     server.register(FastifySecureSession);
   *     server.register(FastifyPassport.initialize());
   *     server.register(FastifyPassport.secureSession());
   *
   * Options:
   *   - `pauseStream`      Pause the request stream before deserializing the user
   *                        object from the session.  Defaults to _false_.  Should
   *                        be set to true in cases where middleware consuming the
   *                        request body is configured after passport and the
   *                        deserializeUser method is asynchronous.
   *
   * @return {Function} middleware
   */
  public secureSession(options?: AuthenticateOptions): FastifyPluginAsync {
    return fastifyPlugin(async (fastify) => {
      fastify.addHook('preValidation', new AuthenticationRoute(this, 'session', options).handler)
    })
  }

  /**
   * Registers a function used to serialize user objects into the session.
   *
   * Examples:
   *
   *     passport.registerUserSerializer(async (user) => user.id);
   *
   * @api public
   */
  registerUserSerializer<User, StoredUser>(fn: SerializeFunction<User, StoredUser>) {
    this.serializers.push(fn)
  }

  /** Runs the chain of serializers to find the first one that serializes a user, and returns it. */
  async serializeUser<User, StoredUser = any>(user: User, request: FastifyRequest): Promise<StoredUser> {
    const result = await this.runStack(this.serializers, user, request)

    if (result) {
      return result
    } else {
      throw new Error(`Failed to serialize user into session. Tried ${this.serializers.length} serializers.`)
    }
  }

  /**
   * Registers a function used to deserialize user objects out of the session.
   *
   * Examples:
   *
   *     fastifyPassport.registerUserDeserializer(async (id) => {
   *       return await User.findById(id);
   *     });
   *
   * @api public
   */
  registerUserDeserializer<StoredUser, User>(fn: DeserializeFunction<StoredUser, User>) {
    this.deserializers.push(fn)
  }

  async deserializeUser<StoredUser>(stored: StoredUser, request: FastifyRequest): Promise<StoredUser | false> {
    const result = await this.runStack(this.deserializers, stored, request)

    if (result) {
      return result
    } else if (result === null || result === false) {
      return false
    } else {
      throw new Error(`Failed to deserialize user out of session. Tried ${this.deserializers.length} serializers.`)
    }
  }

  /**
   * Registers a function used to transform auth info.
   *
   * In some circumstances authorization details are contained in authentication credentials or loaded as part of verification.
   *
   * For example, when using bearer tokens for API authentication, the tokens may encode (either directly or indirectly in a database), details such as scope of access or the client to which the token was issued.
   *
   * Such authorization details should be enforced separately from authentication. Because Passport deals only with the latter, this is the responsibility of middleware or routes further along the chain.  However, it is not optimal to decode the same data or execute the same database query later.  To avoid this, Passport accepts optional `info` along with the authenticated `user` in a strategy's `success()` action.  This info is set at `request.authInfo`, where said later middlware or routes can access it.
   *
   * Optionally, applications can register transforms to process this info, which take effect prior to `request.authInfo` being set.  This is useful, forexample, when the info contains a client ID.  The transform can load the client from the database and include the instance in the transformed info, allowing the full set of client properties to be convieniently accessed.
   *
   * If no transforms are registered, `info` supplied by the strategy will be left unmodified.
   *
   * Examples:
   *
   *     fastifyPassport.registerAuthInfoTransformer(async (info) => {
   *       info.client = await Client.findById(info.clientID);
   *       return info;
   *     });
   *
   * @api public
   */
  registerAuthInfoTransformer(fn: InfoTransformerFunction) {
    this.infoTransformers.push(fn)
  }

  async transformAuthInfo(info: any, request: FastifyRequest) {
    const result = await this.runStack(this.infoTransformers, info, request)
    // if no transformers are registered (or they all pass), the default behavior is to use the un-transformed info as-is
    return result || info
  }

  /**
   * Return strategy with given `name`.
   *
   * @param {String} name
   * @return {AnyStrategy}
   * @api private
   */
  strategy(name: string): AnyStrategy | undefined {
    return this.strategies[name]
  }

  private async runStack<Result, A, B>(stack: ((...args: [A, B]) => Promise<Result>)[], ...args: [A, B]) {
    for (const attempt of stack) {
      try {
        return await attempt(...args)
      } catch (e) {
        if (e === 'pass') {
          continue
        } else {
          throw e
        }
      }
    }
  }
}

export default Authenticator

/**
 * General-purpose sanitization helper to redact sensitive user data from error messages and challenges.
 * This is a best-effort sanitization that redacts:
 * - Bearer tokens and API keys
 * - OAuth tokens and secrets
 * - Password-like strings
 * - Session tokens and cookies
 * - JWT tokens
 * - Email addresses
 * - Common credential patterns
 */
function sanitize(input: string): string {
  const patterns = {
    bearerToken: /bearer\s+(?!realm)[A-Za-z0-9\-._~+/]+=*/gi,
    basicAuth: /basic\s+[A-Za-z0-9+/]+=*/gi,
    jwtToken: /\beyJ[\w\-._~+/]*\.[\w\-._~+/]*\.[\w\-._~+/]*/g,
    hexToken: /\b[a-f0-9]{32,}\b/gi,
    longAlphanumeric: /\b[A-Za-z0-9_\-]{40,}\b/g,
    apiKeyPattern: /\b(api[_-]?key|apikey|access[_-]?token|secret[_-]?key|client[_-]?secret)[\s:=]+[\w\-._~+/]+/gi,
    passwordPattern: /\b(password|passwd|pwd)[\s:=]+\S+/gi,
    emailAddress: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
    sessionToken: /\b(session|sid|connect\.sid)[\s:=]+[\w\-._~+/]+/gi,
    oauthToken: /\b(oauth[_-]?token|oauth[_-]?secret|refresh[_-]?token)[\s:=]+[\w\-._~+/]+/gi,
    authCode: /\b(code|authorization[_-]?code)[\s:=]+[\w\-._~+/]+/gi
  }

  const combinedPattern = new RegExp(
    Object.values(patterns).map(p => `(${p.source})`).join('|'),
    'gi'
  )

  const sanitized = input.replace(combinedPattern, '[REDACTED]')

  // Truncate to reasonable length to prevent overly verbose messages
  const MAX_LENGTH = 500
  if (sanitized.length > MAX_LENGTH) {
    return sanitized.substring(0, MAX_LENGTH).trim() + '...'
  }

  return sanitized.trim()
}