# Implementation plan — pluggable 401/403 handlers (custom `AuthenticationEntryPoint` / `AccessDeniedHandler`)

**Status:** IMPLEMENTED 2026-07-30 (same day as planned; Gökhan + Claude).
Landed on `develop` targeting release `2.2.0` (pom bumped to
`2.2.0-SNAPSHOT`). See §9 for a deviation discovered during implementation.

**Motivation:** security failures are the only error family a consumer service
cannot render today. Authentication (401) and URL-authorization (403) failures
are decided in the Spring Security filter chain, **before the
DispatcherServlet**, so a consumer's `@RestControllerAdvice` never sees them.
The library builds its chains without any `.exceptionHandling(...)`
customization, so Spring Security's resource-server defaults apply
(`BearerTokenAuthenticationEntryPoint` / `BearerTokenAccessDeniedHandler`):
correct status + `WWW-Authenticate` header per RFC 6750, **empty body**. DNMS
services standardize on ProblemDetail bodies for every error (rendered via
`opentmf-errors-spring`), and currently 401/403 break that uniformity with no
supported customization point.

## 1. Current state (verified in source)

- `ServletSecurityAutoConfiguration#servletSecurityFilterChain` — builds
  `HttpSecurity` with `sessionManagement/csrf/formLogin/httpBasic/logout/
  headers/cors/authorizeHttpRequests/oauth2ResourceServer`. No
  `exceptionHandling`, no entry-point/denied-handler wiring.
- `ReactiveSecurityAutoConfiguration#reactiveSecurityFilterChain` — same shape
  on `ServerHttpSecurity`. No `exceptionHandling`.
- `config/management/*` — the management-port chains (child context) likewise
  use defaults.
- Method security is enabled on both stacks (`@EnableMethodSecurity` /
  `@EnableReactiveMethodSecurity`); a `@PreAuthorize` denial *inside* a handler
  already reaches consumer advice — that path is out of scope here and must
  keep working unchanged.

## 2. Design

**Parity principle (Gökhan, 2026-07-30):** this library supports both servlet
and reactive stacks, so every functionality added must land on BOTH. Where the
exact mechanism cannot be mirrored (stack-specific API), an alternative way to
achieve the SAME OUTCOME must be provided and documented. This plan applies
that principle: the hook itself is mechanism-identical on both stacks
(§2.1/§2.2); the one servlet-only mechanism (the `HandlerExceptionResolver`
delegate recipe) gets a reactive equivalent-outcome counterpart (§4).

**The switch is bean presence — no new configuration properties.** If the
consumer's context contains a suitable bean, apply it; otherwise behavior is
byte-for-byte today's defaults. (YAGNI check passed: the "config surface"
alternative — a property naming a handler class — adds indirection for zero
flexibility over plain bean definition.)

### 2.1 Servlet chain

Inject into `ServletSecurityAutoConfiguration`:

```java
private final ObjectProvider<AuthenticationEntryPoint> authenticationEntryPoint;
private final ObjectProvider<AccessDeniedHandler> accessDeniedHandler;
```

Resolve with `getIfUnique()` (two candidate beans = ambiguous = fall back to
defaults **and log a WARN naming both beans**; never guess). Implementation
note: `getIfUnique()` returns `null` on ambiguity without exposing the
candidates — to name them in the WARN, enumerate via `provider.stream()` and
log the candidates' class names. `getIfUnique()` respects `@Primary`, so a
consumer with two candidates disambiguates by marking one `@Primary` — the
README must mention this escape hatch. When present, apply in **both**
places — they cover different failure paths:

1. `.oauth2ResourceServer(rs -> rs.authenticationEntryPoint(ep)
   .accessDeniedHandler(adh)…)` — covers **bearer-token failures**: invalid /
   expired / malformed JWT (the `BearerTokenAuthenticationFilter` path) and
   insufficient-scope denials.
2. `.exceptionHandling(eh -> eh.authenticationEntryPoint(ep)
   .accessDeniedHandler(adh))` — covers the **`ExceptionTranslationFilter`**
   path: anonymous request hitting a protected URL (no token at all → 401) and
   `AuthorizationFilter` denials for authenticated users (role mismatch → 403).

Both must be set; setting only one leaves the other path on the empty-body
default (the ITs in §5 pin each path separately to prove this).

Log at INFO when a custom entry point / denied handler is applied (class name),
mirroring the existing management-chain registration log style.

### 2.2 Reactive chain

Same pattern with the reactive types:

```java
private final ObjectProvider<ServerAuthenticationEntryPoint> entryPoint;
private final ObjectProvider<ServerAccessDeniedHandler> accessDeniedHandler;
```

Applied to `ServerHttpSecurity` via `.oauth2ResourceServer(rs ->
rs.authenticationEntryPoint(…).accessDeniedHandler(…)…)` and
`.exceptionHandling(eh -> eh.authenticationEntryPoint(…)
.accessDeniedHandler(…))`. Servlet and reactive consumers define *different*
bean types, so a consumer can never accidentally cross-wire; no
`@ConditionalOnClass` gymnastics needed beyond what the two auto-configurations
already carry.

### 2.3 Management-port chains: deliberately unchanged

The management chains keep the RFC 6750 defaults. Rationale: the management
port serves probes and scrapers (machines that read status codes, not bodies);
a custom body there buys nothing and risks confusing ops tooling that expects
the bare `WWW-Authenticate` challenge. If a real need ever appears, the same
bean-presence pattern can be extended with qualified beans — do **not**
pre-build that (§ ask-YAGNI-first).

## 3. Non-goals

- **No ProblemDetail rendering inside this library.** No dependency on
  `opentmf-errors` (or any rendering library). The library exposes the hook;
  what the body looks like is entirely the consumer's business. This keeps the
  dependency posture unchanged and avoids coupling two independent opentmf
  release lines.
- **No default "nicer" body.** When no bean is present, defaults stay exactly
  as today — existing consumers see zero behavior change.
- **No change to method-security behavior** (`@PreAuthorize` denials keep
  flowing to consumer `@RestControllerAdvice` as they do now).
- **No new properties** under `opentmf.security.*`.

## 4. README additions (consumer documentation)

Add a "Customizing 401/403 responses" section with:

1. The **plain beans** example — two small `@Bean` definitions rendering
   whatever the consumer wants (for DNMS: ProblemDetail via
   `opentmf-errors-spring` renderers + `CommonErrorCode` 401/403 entries).
2. The **converge-on-one-place** pattern (recommended for consumers who want
   ONE place governing all error rendering) — documented for BOTH stacks per
   the §2 parity principle, with stack-appropriate mechanisms:

   **Servlet — delegate-to-advice:** the entry point / denied handler
   delegates to the `HandlerExceptionResolver` bean (qualifier
   `handlerExceptionResolver`), which routes the exception into the consumer's
   `@RestControllerAdvice` — security errors and MVC errors converge on the
   same `GlobalExceptionMapper`:

   ```java
   @Bean
   AuthenticationEntryPoint problemDetailEntryPoint(
       @Qualifier("handlerExceptionResolver") HandlerExceptionResolver resolver) {
     return (request, response, ex) -> resolver.resolveException(request, response, null, ex);
   }
   ```

   Caveat to document: the advice must then handle
   `AuthenticationException` / `AccessDeniedException` explicitly, and the
   catch-all `Exception` handler must not accidentally downgrade them to 500.

   **Reactive — same outcome, different mechanism.** WebFlux has no
   `HandlerExceptionResolver`; `@ControllerAdvice` exception handling lives
   inside the `DispatcherHandler`, which a `WebFilter`-chain security failure
   never reaches, so the exact servlet trick cannot be ported. Two equivalent
   routes, both to be documented:

   - **Shared-renderer pattern (primary recommendation):** extract the body
     rendering into one injectable component (for DNMS: a thin wrapper over
     the `opentmf-errors-spring` renderers); BOTH the consumer's
     `@RestControllerAdvice` AND the `ServerAuthenticationEntryPoint` /
     `ServerAccessDeniedHandler` beans call it. Convergence happens at the
     renderer instead of the dispatch path — same single source of truth for
     the body shape:

     ```java
     @Bean
     ServerAuthenticationEntryPoint problemDetailEntryPoint(ErrorBodyRenderer renderer) {
       return (exchange, ex) -> renderer.write(exchange, HttpStatus.UNAUTHORIZED, ex);
     }
     ```

   - **Delegate-to-error-handler variant — document as "why not this", not
     as a route.** Returning `Mono.error(ex)` from the beans propagates the
     exception up the `WebFilter` chain into Boot's
     `ErrorWebExceptionHandler` — but `DefaultErrorAttributes` derives the
     HTTP status from `ResponseStatusException` / `@ResponseStatus`, which
     `AuthenticationException` and `AccessDeniedException` carry neither of,
     so **the default outcome is a 500, not 401/403**. It only behaves if the
     consumer's custom `ErrorAttributes` explicitly maps those two exception
     types to 401/403, and the `WWW-Authenticate` challenge is lost
     regardless. The README documents this pitfall briefly so nobody
     "simplifies" toward it; the shared-renderer pattern is the recipe.
3. A short matrix of which failure takes which path (no token / bad token /
   wrong role / method-security denial) so consumers can reason about test
   coverage — one column per stack. Include the two surprise rows: an
   **invalid token sent to a `permitAll` endpoint** still 401s through the
   bearer filter (the custom entry point renders it), and an **anonymous
   request hitting `denyAll`/blacklist** yields 401 via the entry point, not
   403.
4. The explicit note that the management port is NOT affected.

## 5. Tests (extend the existing IT suites — same conventions)

Test tree already covers both stacks (`BaseServletIT`/`BaseReactiveIT` +
local-JWK-set variants + management ITs) with a test `GlobalExceptionHandler`;
follow those conventions. New ITs:

- **Default-behavior pins (regression):** without custom beans — no token →
  401 empty body + `WWW-Authenticate`; expired/garbage token → 401; valid
  token, insufficient role → 403 empty body. (Some of these may already exist —
  extend, don't duplicate.)
- **Custom-bean behavior (servlet + reactive):** register custom entry point +
  denied handler in a test config; assert the custom body/content-type for
  each of the three scenarios above — proving BOTH application points of §2.1
  work (no-token exercises `exceptionHandling`, bad-token exercises the
  resource-server configurer).
- **Ambiguity fallback:** two `AuthenticationEntryPoint` beans → defaults
  apply + WARN logged (assert via a log captor, consistent with existing
  tests' style if precedent exists; otherwise assert the 401-empty-body
  behavior only).
- **Convergence-recipe ITs (both stacks, per the §2 parity principle):**
  servlet — the README's `HandlerExceptionResolver` delegate wired to the
  existing test `GlobalExceptionHandler`; reactive — the shared-renderer
  recipe with a test renderer component used by both a test advice and the
  security beans, asserting identical body shape from both paths. Each proves
  its stack's recommended consumer recipe works end-to-end.
- **Management untouched:** one assertion in the existing management ITs that
  a custom main-chain bean does NOT change the management port's 401 shape.

Coverage/gates: whatever the repo's existing build enforces — do not weaken.

## 6. Versioning & CHANGELOG

- Feature ⇒ **minor**: set the pom to `2.2.0-SNAPSHOT` when starting (it
  currently reads `2.1.1-SNAPSHOT`; latest CHANGELOG section is `2.1.0`).
- New CHANGELOG section `## [2.2.0] - YYYY-MM-DD` (bare numeric heading, above
  `2.1.0`), Keep-a-Changelog style, explanatory paragraphs. Lead with the
  compatibility statement: *no behavior change for consumers that define no
  entry-point/denied-handler beans*.

## 7. Work breakdown

1. Servlet hook (§2.1) — `ObjectProvider` injection + both application points
   + INFO/WARN logging.
2. Reactive hook (§2.2) — same, reactive types.
3. ITs (§5), servlet first, then reactive, then the convergence-recipe ITs
   (both stacks) + management pins.
4. README section (§4).
5. CHANGELOG + version bump (§6).
6. Release `2.2.0` (existing release process; release-only plugins already
   profile-scoped per repo conventions — verify, don't restructure).

## 9. Implementation notes (2026-07-30) — discovered defect, fixed alongside

Writing the §5 management-pin IT exposed a **pre-existing 2.1.0 defect**
unrelated to this feature: on the servlet stack, Spring Boot's
`ServletManagementChildContextConfiguration` exposes the *parent* context's
`springSecurityFilterChain` inside the management child context, so the
management `SecurityFilterChain` registered there in 2.1.0 was never
consulted — the management port was governed by the main-port rules. It went
unnoticed because the library's own `TestApplication` component-scanned the
`@ManagementContextConfiguration` classes into the main context (a second,
masking defect). With Gökhan's approval the servlet management chain now
registers in the **main** context, matched by the request's local port
(captured from the management `WebServerInitializedEvent`), at highest
precedence; the test app now excludes `@ManagementContextConfiguration` from
its scan. Reactive was unaffected. §2.3's "management deliberately unchanged"
still holds for THIS feature's scope: the management chain keeps the RFC 6750
default 401/403 responses, pinned by IT. CHANGELOG 2.2.0 carries the Fixed
entry.

## 8. Follow-ups OUTSIDE this repo (recorded here so they aren't lost)

- **dnms side:** once 2.2.0 is released, the dnms service template gains the
  two ProblemDetail beans (or the delegate-pattern bean) rendering via
  `opentmf-errors-spring` + `CommonErrorCode` 401/403 codes; combined-rules
  §16 gets one line pointing at the hook. Owned by the dnotify-analysis
  session, not this one.
- **opentmf-errors:** check `CommonErrorCode` has suitable 401/403 entries;
  if missing, they ride any next minor of that library (append-only rules
  apply there).
