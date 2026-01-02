import { STATUS_CODES } from 'node:http'
import type { Authenticator } from './Authenticator'
import type { AnyStrategy } from './strategies'
import type { Strategy } from './strategies/base'
import AuthenticationError, { StrategyError } from './errors'
import type { FastifyReply, FastifyRequest } from 'fastify'
import { types } from 'node:util'

type FlashObject = { type?: string; message?: string }
export type FailureObject = {
  challenge?: string | FlashObject
  status?: number
  type?: string
}

declare module '@fastify/secure-session' {
  interface SessionData {
    messages: string[]
    returnTo: string | undefined
  }
}

const addMessage = (request: FastifyRequest, message: string) => {
  const existing = request.session.get('messages')
  const messages = existing ? [...existing, message] : [message]
  request.session.set('messages', messages)
}

export interface AuthenticateOptions {
  scope?: string | string[]
  failureFlash?: boolean | string | FlashObject
  failureMessage?: boolean | string
  successRedirect?: string
  failureRedirect?: string
  failWithError?: boolean
  successFlash?: boolean | string | FlashObject
  successMessage?: boolean | string
  assignProperty?: string
  successReturnToOrRedirect?: string
  state?: string
  authInfo?: boolean
  session?: boolean
  pauseStream?: boolean
  keepSessionInfo?: boolean
}

export type SingleStrategyCallback = (
  request: FastifyRequest,
  reply: FastifyReply,
  err: null | Error,
  user?: unknown,
  info?: unknown,
  status?: number
) => Promise<void>
export type MultiStrategyCallback = (
  request: FastifyRequest,
  reply: FastifyReply,
  err: null | Error,
  user?: unknown,
  info?: unknown,
  statuses?: (number | undefined)[]
) => Promise<void>

export type AuthenticateCallback<StrategyOrStrategies extends string | Strategy | (string | Strategy)[]> =
  StrategyOrStrategies extends any[] ? MultiStrategyCallback : SingleStrategyCallback

const Unhandled = Symbol.for('passport-unhandled')

export class AuthenticationRoute<StrategyOrStrategies extends string | Strategy | (string | Strategy)[]> {
  readonly options: AuthenticateOptions
  readonly strategies: (string | Strategy)[]
  readonly isMultiStrategy: boolean
  readonly authenticator: Authenticator
  readonly callback: AuthenticateCallback<StrategyOrStrategies> | undefined

  /**
   * Create a new route handler that runs authentication strategies.
   *
   * @param authenticator aggregator instance that owns the chain of strategies
   * @param strategyOrStrategies list of strategies this handler tries as string names of registered strategies or strategy instances
   * @param options  options governing behaviour of strategies
   * @param callback optional custom callback to process the result of the strategy invocations
   */
  constructor (
    authenticator: Authenticator,
    strategyOrStrategies: StrategyOrStrategies,
    options?: AuthenticateOptions,
    callback?: AuthenticateCallback<StrategyOrStrategies>
  ) {
    this.options = options || {}
    this.authenticator = authenticator
    this.callback = callback

    // Cast `name` to an array, allowing authentication to pass through a chain of strategies.  The first strategy to succeed, redirect, or error will halt the chain.  Authentication failures will proceed through each strategy in series, ultimately failing if all strategies fail.
    // This is typically used on API endpoints to allow clients to authenticate using their preferred choice of Basic, Digest, token-based schemes, etc. It is not feasible to construct a chain of multiple strategies that involve redirection (for example both Facebook and Twitter), since the first one to redirect will halt the chain.
    if (Array.isArray(strategyOrStrategies)) {
      this.strategies = strategyOrStrategies
      this.isMultiStrategy = true
    } else {
      this.strategies = [strategyOrStrategies]
      this.isMultiStrategy = false
    }
  }

  handler = async (request: FastifyRequest, reply: FastifyReply) => {
    const [failures, , successInfo] = await this.executeStrategies(request, reply)
    if (failures.length > 0) {
      return this.onAllFailed(failures, request, reply)
    }
    // Authentication succeeded
    // Return callback result if callback was provided, otherwise return undefined for backwards compatibility
    if (this.callback) {
      return successInfo
    }
  }

  async executeStrategies (request: FastifyRequest, reply: FastifyReply): Promise<[FailureObject[], string, any]> {
    if (!request.passport) {
      throw new Error('passport.initialize() plugin not in use')
    }
    // accumulator for failures from each strategy in the chain
    const failures: FailureObject[] = []
    let latestStrategyName: string = 'unknown'
    let successInfo: any

    // authContext tracking
    const shouldTrack = request.authContext !== undefined
    let startTime = 0
    let strategyStartTime = 0

    if (shouldTrack) {
      startTime = Date.now()
      const context = request.authContext!

      context.attemptedStrategies = []
      if ('elapsedPerStrategy' in context) {
        context.elapsedPerStrategy = []
      }
      if ('userId' in context) {
        context.userId = this.extractUserId(request.user)
      }
      if ('requestedScope' in context) {
        context.requestedScope = this.extractScope(this.options.scope)
      }
    }

    for (const nameOrInstance of this.strategies) {
      latestStrategyName = this.getStrategyName(nameOrInstance)

      if (shouldTrack) {
        request.authContext!.attemptedStrategies.push(latestStrategyName)
        strategyStartTime = Date.now()
      }

      try {
        successInfo = await this.attemptStrategy(
          failures,
          latestStrategyName,
          this.getStrategy(nameOrInstance),
          request,
          reply
        )

        // Record auth context if set
        if (shouldTrack) {
          if (request.authContext!.elapsedPerStrategy !== undefined) {
            request.authContext!.elapsedPerStrategy.push(Date.now() - strategyStartTime)
          }
          request.authContext!.elapsedMs = Date.now() - startTime
          request.authContext!.status = 'authenticated'
          if ('userId' in request.authContext!) {
            request.authContext!.userId = this.extractUserId(request.user)
          }
        }

        return [[], latestStrategyName, successInfo]
      } catch (e) {
        if (shouldTrack) {
          if (request.authContext!.elapsedPerStrategy !== undefined) {
            request.authContext!.elapsedPerStrategy.push(Date.now() - strategyStartTime)
          }
          request.authContext!.elapsedMs = Date.now() - startTime
          request.authContext!.status = 'rejected'
        }

        if (e === Unhandled) {
          continue
        } else {
          throw new StrategyError((e as Error).message, latestStrategyName)
        }
      }
    }

    return [failures, latestStrategyName, successInfo]
  }

  private extractUserId (user: any): string | undefined {
    if (!user) return undefined
    if (typeof user === 'string') return user
    if (typeof user === 'object' && user.id) {
      return String(user.id)
    }
    return undefined
  }

  private extractScope (scope: string | string[] | undefined): string | undefined {
    if (!scope) return undefined
    if (typeof scope === 'string') return scope
    if (Array.isArray(scope)) return scope.join(' ')
    return undefined
  }

  // Attempts to authenticate with the given strategy, returning the optional success info (or callback result)
  attemptStrategy (
    failures: FailureObject[],
    name: string,
    prototype: AnyStrategy,
    request: FastifyRequest,
    reply: FastifyReply
  ): Promise<any> {
    const strategy = Object.create(prototype) as Strategy

    // This is a messed up way of adapting passport's API to fastify's async world. We create a promise that the strategy's per-call functions close over and resolve/reject with the result of the strategy. This augmentation business is a key part of how Passport strategies expect to work.
    return new Promise<any>((resolve, reject) => {
      /**
       * Authenticate `user`, with optional `info`.
       *
       * Strategies should call this function to successfully authenticate a user.  `user` should be an object supplied by the application after it has been given an opportunity to verify credentials.  `info` is an optional argument containing additional user information.  This is useful for third-party authentication strategies to pass profile details.
       */
      strategy.success = async (user: any, info: { type?: string; message?: string }) => {
        request.log.debug({ strategy: name }, 'passport strategy success')
        info = info || {}

        if (this.callback) {
          return resolve(await this.callback(request, reply, null, user, info))
        }
        this.applyFlashOrMessage('success', request, info)

        if (this.options.assignProperty) {
          request[this.options.assignProperty] = user
          return resolve(info)
        }

        request
          .logIn(user, this.options)
          .catch(reject)
          .then(() => {
            const complete = () => {
              if (this.options.successReturnToOrRedirect) {
                let url = this.options.successReturnToOrRedirect
                const returnTo = request.session?.get('returnTo')
                if (typeof returnTo === 'string') {
                  url = returnTo
                  request.session.set('returnTo', undefined)
                }

                reply.redirect(url)
              } else if (this.options.successRedirect) {
                reply.redirect(this.options.successRedirect)
              }
              return resolve(info)
            }

            if (this.options.authInfo !== false) {
              this.authenticator
                .transformAuthInfo(info, request)
                .catch(reject)
                .then((transformedInfo) => {
                  request.authInfo = transformedInfo
                  complete()
                })
            } else {
              complete()
            }
          })
      }

      /**
       * Fail authentication, with optional `challenge` and `status`, defaulting to 401.
       *
       * Strategies should call this function to fail an authentication attempt.
       */
      strategy.fail = function (challengeOrStatus?: string | number | undefined, status?: number) {
        request.log.trace({ strategy: name }, 'passport strategy failed')

        let challenge
        if (typeof challengeOrStatus === 'number') {
          status = challengeOrStatus
          challenge = undefined
        } else {
          challenge = challengeOrStatus
        }

        // push this failure into the accumulator and attempt authentication using the next strategy
        failures.push({ challenge, status: status! })
        reject(Unhandled)
      }

      /**
       * Redirect to `url` with optional `status`, defaulting to 302.
       *
       * Strategies should call this function to redirect the user (via their user agent) to a third-party website for authentication.
       */
      strategy.redirect = (url: string, status?: number) => {
        request.log.trace({ strategy: name, url }, 'passport strategy redirecting')

        reply.status(status || 302)
        reply.redirect(url)
        resolve(undefined)
      }

      /**
       * Pass without making a success or fail decision.
       *
       * Under most circumstances, Strategies should not need to call this function.  It exists primarily to allow previous authentication state to be restored, for example from an HTTP session.
       */
      strategy.pass = () => {
        request.log.trace({ strategy: name }, 'passport strategy passed')

        reject(Unhandled)
      }

      const error = async (err: Error) => {
        request.log.trace({ strategy: name, err }, 'passport strategy errored')

        if (this.callback) {
          return resolve(await this.callback(request, reply, err))
        }

        reject(err)
      }

      /**
       * Internal error while performing authentication.
       *
       * Strategies should call this function when an internal error occurs during the process of performing authentication; for example, if the user directory is not available.
       */
      strategy.error = error

      request.log.trace({ strategy: name }, 'attempting passport strategy authentication')

      try {
        const result = strategy.authenticate(request, this.options)
        if (types.isPromise(result)) {
          result.catch(error)
        }
      } catch (err) {
        error(err as Error)
      }
    })
  }

  async onAllFailed (failures: FailureObject[], request: FastifyRequest, reply: FastifyReply) {
    request.log.trace('all passport strategies failed')

    if (this.callback) {
      if (this.isMultiStrategy) {
        const challenges = failures.map((f) => f.challenge)
        const statuses = failures.map((f) => f.status)
        return await (this.callback as MultiStrategyCallback)(request, reply, null, false, challenges, statuses)
      } else {
        return await (this.callback as SingleStrategyCallback)(
          request,
          reply,
          null,
          false,
          failures[0].challenge,
          failures[0].status
        )
      }
    }

    // Strategies are ordered by priority.  For the purpose of flashing a message, the first failure will be displayed.
    this.applyFlashOrMessage('failure', request, this.toFlashObject(failures[0]?.challenge, 'error'))
    if (this.options.failureRedirect) {
      return reply.redirect(this.options.failureRedirect)
    }

    // When failure handling is not delegated to the application, the default is to respond with 401 Unauthorized.  Note that the WWW-Authenticate header will be set according to the strategies in use (see actions#fail).  If multiple strategies failed, each of their challenges will be included in the response.
    const rchallenge: string[] = []
    let rstatus: number | undefined

    for (const failure of failures) {
      rstatus = rstatus || failure.status
      if (typeof failure.challenge === 'string') {
        rchallenge.push(failure.challenge)
      }
    }

    rstatus = rstatus || 401
    reply.code(rstatus)

    if (reply.statusCode === 401 && rchallenge.length) {
      reply.header('WWW-Authenticate', rchallenge)
    }

    if (this.options.failWithError) {
      throw new AuthenticationError(STATUS_CODES[reply.statusCode]!, rstatus)
    }

    reply.send(STATUS_CODES[reply.statusCode])
  }

  applyFlashOrMessage (event: 'success' | 'failure', request: FastifyRequest, result?: FlashObject) {
    const flashOption = this.options[`${event}Flash`]
    const level = event === 'success' ? 'success' : 'error'

    if (flashOption) {
      let flash: FlashObject | undefined
      if (typeof flashOption === 'boolean') {
        flash = this.toFlashObject(result, level)
      } else {
        flash = this.toFlashObject(flashOption, level)
      }

      if (flash && flash.type && flash.message) {
        request.flash(flash.type, flash.message)
      }
    }

    const messageOption = this.options[`${event}Message`]
    if (messageOption) {
      const message = typeof messageOption === 'boolean' ? this.toFlashObject(result, level)?.message : messageOption
      if (message) {
        addMessage(request, message)
      }
    }
  }

  toFlashObject (input: string | FlashObject | undefined, type: string) {
    if (input === undefined) {
      // fall-through
    } else if (typeof input === 'string') {
      return { type, message: input }
    } else {
      return input
    }
  }

  private getStrategyName (nameOrInstance: string | Strategy): string {
    if (typeof nameOrInstance === 'string') {
      return nameOrInstance
    } else if (nameOrInstance.name) {
      return nameOrInstance.name
    } else {
      return nameOrInstance.constructor.name
    }
  }

  private getStrategy (nameOrInstance: string | Strategy): AnyStrategy {
    if (typeof nameOrInstance === 'string') {
      const prototype = this.authenticator.strategy(nameOrInstance)
      if (!prototype) {
        throw new Error(
          `Unknown authentication strategy ${nameOrInstance}, no strategy with this name has been registered.`
        )
      }
      return prototype
    } else {
      return nameOrInstance
    }
  }
}
