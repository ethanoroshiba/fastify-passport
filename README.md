# @fastify/passport

[![CI](https://github.com/fastify/fastify-passport/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/fastify/fastify-passport/actions/workflows/ci.yml)
[![NPM version](https://img.shields.io/npm/v/@fastify/passport.svg?style=flat)](https://www.npmjs.com/package/@fastify/passport)
[![neostandard javascript style](https://img.shields.io/badge/code_style-neostandard-brightgreen?style=flat)](https://github.com/neostandard/neostandard)

`@fastify/passport` is a port of [`passport`](http://www.passportjs.org/) for the Fastify ecosystem. It lets you use Passport strategies to authenticate requests and protect Fastify routes!

## Status

Beta. `@fastify/passport` is still a relatively new project. There may be incompatibilities with express-based `passport` deployments, and bugs. Please report any issues so we can correct them!

## Installation

```shell
npm i @fastify/passport
```

## Google OAuth2 Video tutorial

The community created this fast introduction to `@fastify/passport`:
[![Google OAuth2 Tutorial Passport](https://img.youtube.com/vi/XRcQQWU0XOM/0.jpg)](https://youtu.be/XRcQQWU0XOM)


## Example

### Quick Start: Hook-Based Authentication

```js
import fastifyPassport from '@fastify/passport'
import fastifySecureSession from '@fastify/secure-session'

const server = fastify()
// set up secure sessions for @fastify/passport to store data in
server.register(fastifySecureSession, { key: fs.readFileSync(path.join(__dirname, 'secret-key')) })
// initialize @fastify/passport and connect it to the secure-session storage. Note: both of these plugins are mandatory.
server.register(fastifyPassport.initialize())
server.register(fastifyPassport.secureSession())

// register an example strategy for fastifyPassport to authenticate users using
fastifyPassport.use('test', new SomePassportStrategy()) // you'd probably use some passport strategy from npm here

// Add an authentication for a route that will use the strategy named "test" to protect the route
server.get(
  '/',
  { preValidation: fastifyPassport.authenticate('test', { authInfo: false }) },
  async () => 'hello world!'
)

// Add an authentication for a route that will use the strategy named "test" to protect the route, and redirect on success to a particular other route.
server.post(
  '/login',
  { preValidation: fastifyPassport.authenticate('test', { successRedirect: '/', authInfo: false }) },
  () => {}
)

server.listen()
```

### Programmatic Authentication Example

For API endpoints that need custom response handling:

```js
import { Authenticator } from '@fastify/passport'
import fastifySecureSession from '@fastify/secure-session'

const server = fastify()
const fastifyPassport = new Authenticator()

server.register(fastifySecureSession, { key: fs.readFileSync(path.join(__dirname, 'secret-key')) })
server.register(fastifyPassport.initialize())
server.register(fastifyPassport.secureSession())

fastifyPassport.use('local', new LocalStrategy())

// Login endpoint with custom response format
server.post('/api/login', async (request, reply) => {
  const result = await fastifyPassport.authenticateRequest(
    'local',
    request,
    reply,
    { session: true }
  )

  if (result.ok) {
    return {
      success: true,
      user: result.user,
      message: 'Login successful'
    }
  } else {
    return reply.code(result.status || 401).send({
      success: false,
      error: result.challenges?.[0] || 'Authentication failed'
    })
  }
})

// Protected endpoint
server.get('/api/profile', async (request, reply) => {
  const result = await fastifyPassport.authenticateRequest(
    ['jwt', 'session'],
    request,
    reply
  )

  if (!result.ok) {
    return reply.code(401).send({ error: 'Authentication required' })
  }

  return { profile: result.user }
})

server.listen()
```

Alternatively, [`@fastify/session`](https://github.com/fastify/session) is also supported and works out of the box for session storage.
Here's an example:

```js
import { Authenticator } from '@fastify/passport'
import fastifyCookie from '@fastify/cookie'
import fastifySession from '@fastify/session'

const server = fastify()

// setup an Authenticator instance which uses @fastify/session
const fastifyPassport = new Authenticator()

server.register(fastifyCookie)
server.register(fastifySession, { secret: 'secret with minimum length of 32 characters' })

// initialize @fastify/passport and connect it to the secure-session storage. Note: both of these plugins are mandatory.
server.register(fastifyPassport.initialize())
server.register(fastifyPassport.secureSession())

// register an example strategy for fastifyPassport to authenticate users using
fastifyPassport.use('test', new SomePassportStrategy()) // you'd probably use some passport strategy from npm here
```

## Session cleanup on logIn

For security reasons the session is cleaned after login. You can manage this configuration at your own risk by:
1) Include `keepSessionInfo` true option when perform the passport `.authenticate` call;
2) Include `keepSessionInfo` true option when perform the request `.login` call;
3) Using `clearSessionOnLogin (default: true)` and `clearSessionIgnoreFields (default: ['passport', 'session'])`.

## Difference between `@fastify/secure-session` and `@fastify/session`
`@fastify/secure-session` and `@fastify/session` are both session plugins for Fastify which are capable of encrypting/decrypting the session. The main difference is that `@fastify/secure-session` uses the stateless approach and stores the whole session in an encrypted cookie whereas `@fastify/session` uses the stateful approach for sessions and stores them in a session store.

## Session Serialization

In a typical web application, the credentials used to authenticate a user will only be transmitted once when a user logs in, and after, they are considered logged in because of some data stored in their session. `@fastify/passport` implements this pattern by storing sessions using `@fastify/secure-session`, and serializing/deserializing user objects to and from the session referenced by the cookie. `@fastify/passport` cannot store rich object classes in the session, only JSON objects, so you must register a serializer/deserializer pair if you want to fetch a User object from your database, and store only a user ID in the session.

```js
// register a serializer that stores the user object's id in the session ...
fastifyPassport.registerUserSerializer(async (user, request) => user.id);

// ... and then a deserializer that will fetch that user from the database when a request with an id in the session arrives
fastifyPassport.registerUserDeserializer(async (id, request) => {
  return await User.findById(id);
});
```

## API

### initialize()

A hook that **must be added**. Sets up a `@fastify/passport` instance's hooks.

### secureSession()

A hook that **must be added**. Sets up `@fastify/passport`'s connector with `@fastify/secure-session` to store authentication in the session.

## Authentication Methods

`@fastify/passport` provides two approaches for authenticating requests: **hook-based** and **programmatic**. Both approaches support the same strategies and options, but differ in how they handle authentication results.

### AuthContext: request.authContext (opt-in observability)

`@fastify/passport` can optionally populate **per-request authentication metadata** on `request.authContext`. This is designed for audit logs, metrics, and debugging without leaking sensitive values (it does **not** include passwords, tokens, full user objects, strategy errors, etc.).

- **Opt-in per request**: `authContext` is only recorded if you set `request.authContext` to an object at the start of the request lifecycle (for example, in an `onRequest` hook). By default it is `undefined`.
- **Same for both approaches**: it works the same whether you use the hook-based `authenticate()` or programmatic `authenticateRequest()`.
- **“Include the key to enable it”**: some fields are only populated if you include that key in the object you set. (This allows you to decide what gets recorded.)

`AuthContext` shape:

```typescript
interface AuthContext {
  attemptedStrategies: string[]
  elapsedMs: number
  status: 'authenticated' | 'rejected'
  elapsedPerStrategy?: number[] // index-aligned with attemptedStrategies
  userId?: string
  requestedScope?: string
}
```

**How to enable it (recommended pattern):**

```js
// Enable AuthContext on every request (or do this only for routes you care about)
server.addHook('onRequest', async (request) => {
  request.authContext = {
    attemptedStrategies: [],
    elapsedMs: 0,
    status: 'rejected',

    // Optional fields: include the key to opt in
    elapsedPerStrategy: [],
    userId: '',
    requestedScope: ''
  }
})

// Example: safe audit logging
server.addHook('onResponse', async (request, reply) => {
  if (request.authContext) {
    request.log.info(
      { auth: request.authContext, statusCode: reply.statusCode },
      'auth attempt'
    )
  }
})
```

### Hook-Based: authenticate(strategy, options, callback?)

**When to use:** Standard authentication flows where you want automatic handling of success/failure (redirects, status codes, etc.).

Returns a hook that authenticates requests and automatically handles responses. Use this as a `preValidation` hook on routes like `/login`.

```js
// Automatic handling - redirects on success/failure
server.post(
  '/login',
  { preValidation: fastifyPassport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/login'
  })},
  () => {}
)

// Automatic 401 response on failure
server.get(
  '/protected',
  { preValidation: fastifyPassport.authenticate('jwt') },
  async (request) => {
    // If enabled, AuthContext is available here too:
    // request.log.info({ auth: request.authContext }, 'auth details')
    return { user: request.user }
  }
)
```

### Programmatic: authenticateRequest(strategy, request, reply, options?)

**When to use:** Custom authentication flows where you need fine-grained control over the response based on the authentication result.

Authenticates a request and returns an `AuthResult` object, giving you full control over how to handle success or failure. Use this inside route handlers when you need to inspect the authentication result before responding.

```typescript
interface AuthResult {
  ok: boolean              // true if authentication succeeded
  strategy: string         // name of the strategy used
  user?: PassportUser      // authenticated user (if ok: true)
  info?: object           // additional info from strategy
  status?: 401 | 403      // HTTP status code (if ok: false)
  error?: Error           // error details (if ok: false)
  challenges?: string[]   // failure messages from strategies
}
```

```js
// Custom success/failure handling
server.post('/api/login', async (request, reply) => {
  const result = await fastifyPassport.authenticateRequest(
    'local',
    request,
    reply,
    { session: true }
  )

  if (result.ok) {
    return {
      success: true,
      user: result.user,
      // If enabled, AuthContext is populated by the call above:
      auth: request.authContext,
      token: generateToken(result.user)
    }
  } else {
    return reply.code(result.status || 401).send({
      success: false,
      auth: request.authContext,
      message: result.challenges?.[0] || 'Authentication failed'
    })
  }
})

// Try multiple strategies with custom fallback logic
server.get('/api/user', async (request, reply) => {
  const result = await fastifyPassport.authenticateRequest(
    ['jwt', 'bearer', 'session'],
    request,
    reply
  )

  if (!result.ok) {
    // Log failed strategy for monitoring
    request.log.warn({ strategy: result.strategy }, 'Auth failed')
    return reply.code(401).send({ error: 'Unauthorized' })
  }

  return { user: result.user }
})
```

### Choosing Between Them

| Use Case | Recommended Approach | Why |
|----------|---------------------|-----|
| Traditional login forms with redirects | `authenticate` hook | Automatically handles redirects and flash messages |
| API endpoints returning JSON | `authenticateRequest` | Custom response format and error handling |
| Simple route protection | `authenticate` hook | Less boilerplate, automatic 401 responses |
| Multi-step authentication flows | `authenticateRequest` | Inspect results between steps |
| Custom error messages/logging | `authenticateRequest` | Access to detailed failure information |
| OAuth callback handlers | `authenticate` hook | Built-in redirect handling |

### Migration guidance (existing users)

If you’re already using `authenticate()` hooks, you can adopt `AuthContext` **without changing your authentication flow**:

- **What stays the same**: strategies, `authenticate()`/`authorize()` usage, sessions (`secureSession()` / `@fastify/session`), and `request.user` behavior.
- **What gets easier**: consistent audit logs and metrics (which strategies ran, how long they took, overall outcome) across *both* hook-based and programmatic flows—without needing to parse strategy errors or serialize sensitive objects.
- **How to adopt**:
  - Add an `onRequest` hook to initialize `request.authContext` (see the example above), or do it only for routes where you want telemetry.
  - Optionally include `elapsedPerStrategy`, `userId`, and/or `requestedScope` keys to opt into recording those fields.

You can still adopt `authenticateRequest()` incrementally for routes needing custom response behavior; `AuthContext` works the same either way.

### Common Options (both methods)

Both `authenticate()` and `authenticateRequest()` support the following options:

- `session` Save login state in session, defaults to _true_
- `assignProperty` Assign the object provided by the verify callback to given property
- `state` Pass any provided state through to the strategy (e.g. for Google Oauth)
- `keepSessionInfo` True to save existing session properties after authentication

### authenticate() Specific Options

The hook-based `authenticate()` method supports additional options for automatic response handling:

- `successRedirect` After successful login, redirect to given URL
- `successMessage` True to store success message in req.session.messages, or a string to use as override message for success
- `successFlash` True to flash success messages or a string to use as a flash message for success (overrides any from the strategy itself)
- `failureRedirect` After failed login, redirect to given URL
- `failureMessage` True to store failure message in req.session.messages, or a string to use as override message for failure
- `failureFlash` True to flash failure messages or a string to use as a flash message for failures (overrides any from the strategy itself)

### authenticate() Callback

The hook-based `authenticate()` can optionally accept a callback to override default authentication handling. The callback has the following signature:

```js
(request, reply, err | null, user | false, info?, (status | statuses)?) => Promise<void>
```

where `request` and `reply` will be set to the original `FastifyRequest` and `FastifyReply` objects, and `err` will be set to `null` in case of a success or an `Error` object in case of a failure. If `err` is not `null` then `user`, `info`, and `status` objects will be `undefined`. The `user` object will be set to the authenticated user on a successful authentication attempt, or `false` otherwise.

An optional `info` argument will be passed, containing additional details provided by the strategy's verify callback - this could be information about a successful authentication or a challenge message for a failed authentication.

An optional `status` or `statuses` argument will be passed when authentication fails - this could be a HTTP response code for a remote authentication failure or similar.

```js
fastify.get(
  '/',
  { preValidation: fastifyPassport.authenticate('test', { authInfo: false }) },
  async (request, reply, err, user, info, status) => {
    if (err !== null) {
      console.warn(err)
    } else if (user) {
      console.log(`Hello ${user.name}!`)
    }
  }
)
```

**Note:** When using a callback with `authenticate()`, it becomes your responsibility to log in the user and handle the response. For most custom authentication handling needs, `authenticateRequest()` is simpler as it returns a structured result.

### authenticate() Examples

```js
// create a request handler that uses the Facebook strategy
fastifyPassport.use(new FacebookStrategy('facebook', {
  // options for the Facebook strategy, see https://www.npmjs.com/package/passport-facebook
})))
fastifyPassport.authenticate('facebook');

// create a request handler to test against the strategy named local, and automatically redirect when it succeeds or fails
fastifyPassport.authenticate('local', { successRedirect: '/', failureRedirect: '/login' });

// create a request handler that won't use any user information stored in the secure session
fastifyPassport.authenticate('basic', { session: false });
```

### Multiple Strategies

Both `authenticate()` and `authenticateRequest()` support authenticating with multiple strategies by passing an array. The strategies will be tried in order until one succeeds:

```js
// somewhere before several strategies are registered
fastifyPassport.use('bearer', new BearerTokenStrategy())
fastifyPassport.use('basic', new BasicAuthStrategy())
fastifyPassport.use('google', new FancyGoogleStrategy())

// Hook-based: authenticate against multiple strategies
fastify.get(
  '/',
  { preValidation: fastifyPassport.authenticate(['bearer', 'basic', 'google']) },
  async (request, reply) => `Hello ${request.user.name}!`
)

// Programmatic: authenticate against multiple strategies
fastify.get('/api/data', async (request, reply) => {
  const result = await fastifyPassport.authenticateRequest(
    ['bearer', 'basic', 'google'],
    request,
    reply
  )

  if (!result.ok) {
    return reply.code(401).send({ error: 'Authentication required' })
  }

  return { data: 'sensitive information', user: result.user }
})
```

**Note:** Multiple strategies that redirect to start an authentication flow (like OAuth2) should not be used together in the same call, as the first one will redirect and prevent others from running. Instead, create separate routes for each OAuth2 strategy.

Strategies can also be passed as instances (useful for temporary, one-time use):

```js
// Use strategies without registering them globally
fastify.get(
  '/',
  {
    preValidation: fastifyPassport.authenticate(
      [new BearerTokenStrategy(), new BasicAuthStrategy()],
      { authInfo: false }
    ),
  },
  async (request, reply) => `Hello ${request.user.name}!`
)

// Or with authenticateRequest
fastify.post('/api/verify', async (request, reply) => {
  const result = await fastifyPassport.authenticateRequest(
    [new BearerTokenStrategy(), new BasicAuthStrategy()],
    request,
    reply
  )

  if (result.ok) {
    return { verified: true, user: result.user }
  }
  return reply.code(401).send({ verified: false })
})
```

### authorize(strategy: string | Strategy | (string | Strategy)[], options: AuthenticateOptions = {}, callback?: AuthenticateCallback)

Returns a hook that will authorize a third-party account using the given `strategy`, with optional `options`. Intended for use as a `preValidation` hook on any route. `.authorize` has the same API as `.authenticate`, but has one key difference: it doesn't modify the logged in user's details. Instead, if authorization is successful, the result provided by the strategy's verify callback will be assigned to `request.account`. The existing login session and `request.user` will be unaffected.

This function is particularly useful when connecting third-party accounts to the local account of a user that is currently authenticated.

Examples:

```js
fastifyPassport.authorize('twitter-authz', { failureRedirect: '/account' })
```

`.authorize` allows the use of multiple strategies by passing an array of strategy names and allows the use of already instantiated Strategy instances by passing the instance as the strategy, or an array of instances.

### use(name?: string, strategy: Strategy)

Utilize the given `strategy` with optional `name`, overridding the strategy's default name.

Examples:

```js
fastifyPassport.use(new TwitterStrategy(...));

fastifyPassport.use('api', new http.Strategy(...));
```

### unuse(name: string)

Un-utilize the `strategy` with given `name`.

In typical applications, the necessary authentication strategies are static, configured once and always available. As such, there is often no need to invoke this function.

However, in certain situations, applications may need dynamically configure and de-configure authentication strategies. The `use()`/`unuse()` combination satisfies these scenarios.

Example:

```js
fastifyPassport.unuse('legacy-api')
```

### registerUserSerializer(serializer: (user, request) => Promise<SerializedUser>)

Registers an async user serializer function for taking a high-level User object from your application and serializing it for storage into the session. `@fastify/passport` cannot store rich object classes in the session, only JSON objects, so you must register a serializer/deserializer pair if you want to fetch a User object from your database, and store only a user ID in the session.

```js
// register a serializer that stores the user object's id in the session ...
fastifyPassport.registerUserSerializer(async (user, request) => user.id)
```

### registerUserDeserializer(deserializer: (serializedUser, request) => Promise<User>)

Registers an async user deserializer function for taking a low-level serialized user object (often just a user ID) from a session, and deserializing it from storage into the request context. `@fastify/passport` cannot store rich object classes in the session, only JSON objects, so you must register a serializer/deserializer pair if you want to fetch a User object from your database, and store only a user ID in the session.

```js
fastifyPassport.registerUserDeserializer(async (id, request) => {
  return await User.findById(id);
});
```

Deserializers can throw the string `"pass"` if they do not apply to the current session and the next deserializer should be tried. This is useful if you are using `@fastify/passport` to store two different kinds of user objects. An example:

```js
// register a deserializer for database users
fastifyPassport.registerUserDeserializer(async (id, request) => {
  if (id.startsWith("db-")) {
    return await User.findById(id);
  } else {
    throw "pass"
  }
});

// register a deserializer for redis users
fastifyPassport.registerUserDeserializer(async (id, request) => {
  if (id.startsWith("redis-")) {
    return await redis.get(id);
  } else {
    throw "pass"
  }
});
```

Sessions may specify serialized users that have since been deleted from the datastore storing them for the application. In that case, deserialization often fails because the user row cannot be found for a given id. Depending on the application, this can either be an error condition, or expected if users are deleted from the database while logged in. `@fastify/passport`'s behavior in this case is configurable. Errors are thrown if a deserializer returns undefined, and the session is logged out if a deserializer returns `null` or `false.` This matches the behavior of the original `passport` module.

Therefore, a deserializer can return several things:

- if a deserializer returns an object, that object is assumed to be a successfully deserialized user
- if a deserializer returns `undefined`, `@fastify/passport` interprets that as an erroneously missing user, and throws an error because the user could not be deserialized.
- if a deserializer returns `null` or `false`, `@fastify/passport` interprets that as a missing but expected user, and resets the session to log the user out
- if a deserializer throws the string `"pass"`, `@fastify/passport` will try the next deserializer if it exists, or throw an error because the user could not be deserialized.

### Request#isUnauthenticated()

Test if request is unauthenticated.

## Using with TypeScript

`@fastify/passport` is written in TypeScript, so it includes type definitions for all of its API. You can also strongly type the `FastifyRequest.user` property using TypeScript declaration merging. You must re-declare the `PassportUser` interface in the `fastify` module within your own code to add the properties you expect to be assigned by the strategy when authenticating:

```typescript
declare module 'fastify' {
  interface PassportUser {
    id: string
  }
}
```

or, if you already have a type for the objects returned from all of the strategies, you can make `PassportUser` extend it:

```typescript
import { User } from './my/types'

declare module 'fastify' {
  interface PassportUser extends User {}
}
```

The `AuthResult` type returned by `authenticateRequest()` is also exported:

```typescript
import { AuthResult } from '@fastify/passport'

const result: AuthResult = await fastifyPassport.authenticateRequest('local', request, reply)
if (result.ok) {
  // result.user is typed as PassportUser
  console.log(result.user)
}
```

## Using multiple instances

`@fastify/passport` supports being registered multiple times in different plugin encapsulation contexts. This is useful to implement two separate authentication stacks. For example, you might have a set of strategies that authenticate users of your application and a whole other set of strategies for authenticating staff members of your application that access an administration area. Users might be stored at `request.user`, and administrators at `request.admin`, and logging in as one should have no bearing on the other. It is important to register each instance of `@fastify/passport` in a different Fastify plugin context so that the decorators `@fastify/passport` like `request.logIn` and `request.logOut` do not collide.

To register @fastify/passport more than once, you must instantiate more copies with different `keys` and `userProperty`s so they do not collide when decorating your fastify instance or storing things in the session.

```typescript
import { Authenticator } from '@fastify/passport'

const server = fastify()

// setup an Authenticator instance for users that stores the login result at `request.user`
const userPassport = new Authenticator({ key: 'users', userProperty: 'user' })
userPassport.use('some-strategy', new CoolOAuthStrategy('some-strategy'))
server.register(userPassport.initialize())
server.register(userPassport.secureSession())

// setup an Authenticator instance for users that stores the login result at `request.admin`
const adminPassport = new Authenticator({ key: 'admin', userProperty: 'admin' })
adminPassport.use('admin-google', new GoogleOAuth2Strategy('admin-google'))
server.register(adminPassport.initialize())
server.register(adminPassport.secureSession())

// protect some routes with the userPassport
server.get(
  `/`,
  { preValidation: userPassport.authenticate('some-strategy') },
  async () => `hello ${JSON.serialize(request.user)}!`
)

// and protect others with the adminPassport
server.get(
  `/admin`,
  { preValidation: adminPassport.authenticate('admin-google') },
  async () => `hello administrator ${JSON.serialize(request.admin)}!`
)
```

**Note**: Each `Authenticator` instance's initialize plugin and session plugin must be registered separately.

It is important to note that using multiple `@fastify/passport` instances is not necessary if you want to use multiple strategies to login the same type of user. `@fastify/passport` supports multiple strategies by passing an array to any `.authenticate` call.

# Differences from Passport.js

`@fastify/passport` is an adapted version of Passport that tries to be as compatible as possible but is an adapted version that has some incompatibilities. Passport strategies that adhere to the passport strategy API should work fine, but there are some differences in other APIs made to integrate better with Fastify and to stick with Fastify's theme of performance.

Differences:

- `serializeUser` renamed to `registerUserSerializer` and always takes an async function with the signature `(user: User, request: FastifyRequest) => Promise<SerializedUser>`
- `deserializeUser` renamed to `registerUserDeserializer` and always takes an async function with the signature `(serialized: SerializedUser, request: FastifyRequest) => Promise<User>`
- `transformAuthInfo` renamed to `registerAuthInfoTransformer` and always takes an async function with the signature `(info: any, request: FastifyRequest) => Promise<any>`
- `.authenticate` and `.authorize` accept strategy instances in addition to strategy names. This allows for using one-time strategy instances (say for testing given user credentials) without adding them to the global list of registered strategies.

## License

[MIT](./LICENSE)
