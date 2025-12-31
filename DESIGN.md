# Challenge Step 1
    For the first step of the challenge, I began by basically copying and pasting
the suggested function signature and `AuthResult` shape to the codebase. I entertained
the idea of changing the `statusCode` field to `statusCodes` to accurately reflect
any multitude of codes returned by the failing strategies, but figured that the
challenges themselves should contain sufficient information to act upon. I also
thought of only passing a user ID as well as making errors and info as strings to avoid
leakage of potentially sensitive information, but after considering that the caller
of this API would be server-side and would have agency to use these fields as necessary,
I elected against it. Still, to heed the warning in the instructions about ensuring
no leakage of sensitive information, I removed all information from the error except
for the message, and created a best-effort helper to sanitize common fields that
could be contained in ill-constructed strategy responses. If I were the owner of
the codebase, I would likely enforce more strongly-typed errors in strategies to
discourage users from including sensitive information in their strategy responses.
    After the initial copy-paste I used AI to generate fairly comprehensive unit
tests for the new method and began implementing the method itself. Since the logic
for attempting strategies already existed in `AuthenticationRoute` and was used
by `Authenticator.authenticate`, I performed a refactor to expose the strategy
execution such that both the handler and `Authenticator` could use it. This also
required changing some return types to bubble up information related to failing
and/or succeeding strategies, but the existing functionality of the handler and
`Authenticator.authenticate` should remain unchanged, except for the case listed
below.
    The only breaking change I've made is to the `strategy.pass` behavior. Previously,
it called `resolve()`, which functioned the same as a successful authentication
attempt. This seems to me like it was a bug, and I've replaced it with logic which
calls `reject()` but doesn't add a failure to the failure list, achieving the
"neither failure nor success" functionality.

# Challenge Step 2
    In designing `AuthContext`, I mostly kept the structure outlined in the instructions,
but instead of only including one strategy, I used a list to account for multiple
strategies being used. I also changed `scopes` to be `requestedScope`, since the
same scope is provided to all strategies for the given auth run. If we wanted to
support multiple auth runs per request, this would require some additional logic
and a more complicated `AuthContext` type to associate the correct information
with each run. I also removed `attempts` since the same strategy isn't retried
multiple times in the same auth call unless explicitly included multiple times in
the strategy list, which would be reflected in `strategies`. Finally, I included
an optional `elapsedPerStrategy` field so that callers can optionally see the amount
of time each strategy in the strategy list took. This will be index-aligned with
`attemptedStrategies`. These fields should prevent any leaking of sensitive user
information, as no details about errors, challenges, or success info is included.
To address the optional fields in `AuthContext`, I went with an "opt-in" approach
such that if no authContext is provided, none is set on the request, with the same
logic applied to the optional fields of `AuthContext`.
    I also opted not to pursue the event-driven approach, since taking an `AuthResult`
and logging with the information provided by it 1. exposes information that intentionally
isn't included in `AuthContext`, and 2. doesn't allow for capturing other information
included in `AuthContext` such as scope and elapsed time per strategy. If I had
more time and were the code owner, I would also make it such that the auth context
options and event-driven observability was configured as a part of the server.
This would make the `AuthContext` interface a little less awkward (instead of relying
on which fields exist to know which to populate) and would allow for safe telemetry
via a separate endpoint.
