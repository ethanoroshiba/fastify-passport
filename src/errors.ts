export class AuthenticationError extends Error {
  status: number

  constructor (message: string, status: number) {
    super()

    Error.captureStackTrace(this, this.constructor)
    this.name = 'AuthenticationError'
    this.message = message
    this.status = status || 401
  }
}

export default AuthenticationError

// Wrapper type for strategy errors to allow strategy name to be passed to handlers
export class StrategyError extends Error {
  strategy: string

  constructor (message: string, strategy: string) {
    super(message)
    this.strategy = strategy
  }
}
