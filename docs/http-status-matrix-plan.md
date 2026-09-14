# The HTTP-status matrix — implementation plan (3.1.0)

| | |
|---|---|
| **Status** | Implemented on `feat/http-status-matrix` — §3 reads as built, §6 records what implementation changed against the first draft |
| **Target** | **3.1.0** (Gökhan's ruling, 2026-09-15; BREAKING for anyone relying on 401/403 for unknown paths or on the `Allow` header of a 405 — headlined in the CHANGELOG) |
| **Written** | 2026-09-15, against released 3.0.0 (`docs/http-method-semantics-plan.md` is the 3.0.0 plan this one supersedes in part) |
| **Verified against** | Spring Boot 4.1.1: Spring Security **7.1.1**, Spring Framework **7.0.9**, Tomcat 11.0.24 — resolved with the 3.0.0 plan's §0 recipe on 2026-09-15 |
| **Origin** | DNMS security wave 2026-09-14: measured on dnms-catalog 1.3.1 and dnms-681 1.3.0 (`to-be-resources/opentmf-openid-rbac-security/implementation-plan.md` in `pia-team/dnotify-analysis`) |

## 1. The contract (the whole point — implemented ONCE, tested as a table)

Evaluated in this order, by this library, for every request, before anything else answers:

| # | condition | answer |
|---|---|---|
| 1 | no handler exists for the path | **404** — anonymous or authenticated |
| 2 | the path exists, the HTTP method is not implemented on it — unknown method NAMES (`PROPFIND`, `BREW`, …) included | **405** — **no `Allow` header** ("there is nothing to allow, it is 405") |
| 3 | path and method exist, no token or an invalid one | **401** |
| 4 | a valid token whose roles do not satisfy the rule | **403** |

The body is always the APPLICATION's error rendering (a `HandlerExceptionResolver` / problem+json controller, or a
TMF-`Error` adopter's controller); Spring Boot's default error JSON must never appear. Non-disclosure of path
existence to anonymous callers is dropped by this contract (stated once, accepted by the ruling).

## 2. Why 3.0.0 did not deliver it (so this does not loop again)

- Filters run before servlets: this library decides before the DispatcherServlet looks up a handler. Its rule for a
  path outside `secure-endpoints` was "deny" → 401 anonymous / 403 authenticated — a non-disclosure posture that was
  never tested against the matrix above.
- 3.0.0 fixed ONE cell — an unimplemented method on a mapped path → 405 (`MethodNotAllowedAccessDeniedHandler`,
  bodiless, with `Allow`, anonymous → 401) — and left the others: unknown paths → 401/403; unknown method NAMES →
  Spring Security's `StrictHttpFirewall` answers 400 with Boot's default JSON before the chain; a whitelisted path +
  unknown method → the servlet's 501, Boot JSON again.
- Measured 2026-09-14 (reader token, through the DNMS ingress): `GET /dnms/681/v1/nope` → 403;
  `GET /catalog/feature/wave1/spec/NOT_L2O-10` (a path variable carrying `/`, falls off the route table) → 403 for
  admin AND reader; `PATCH /communicationMessage` → 401 anonymous / bodiless 405 + Allow authenticated;
  `PROPFIND` / `BREW` → 400 Boot JSON.

## 3. Design

### 3.1 Servlet stack (`ServletSecurityAutoConfiguration`, `ServletManagementSecurityAutoConfiguration`)

1. **404 first, from the dispatcher's own mappings.** `ServletHttpStatusMatrixFilter`, added with
   `addFilterBefore(…, BearerTokenAuthenticationFilter.class)`, asks `ServletSupportedMethodsResolver`
   whether ANY handler serves the request path. The resolver consults every `HandlerMapping` bean of the
   dispatching context (`beansOfTypeIncludingAncestors` for the main context, `getBeansOfType` on the
   child for the management port — each exactly what that context's `DispatcherServlet` detects), sorted
   with `AnnotationAwareOrderComparator`, and stops at the first that claims the path, as the dispatcher
   would. A `RequestMappingInfoHandlerMapping` is matched through its infos on the path alone (Spring's
   own patterns condition), so the declared methods are known without a method-mismatch exception; every
   other mapping is asked `getHandler(probe)` on a probe request whose attributes are its own (the device
   `HandlerMappingIntrospector` uses), so nothing a mapping caches leaks into the real request. A
   `ResourceHttpRequestHandler` claims the path only when the resource resolves through the handler's own
   resolvers and locations — Boot maps one to `/**` by default, and without that check no path would
   ever be unknown; a miss ends the lookup as the dispatcher's `NoResourceFoundException` would. The
   methods of any other non-annotation handler are its own business (it proceeds); a resource handler
   publishes GET/HEAD. None → `404` through the application's `HandlerExceptionResolver`s (sorted, first
   non-null wins — the dispatcher's algorithm) with a `NoHandlerFoundException`; a bare status with
   `Content-Length: 0` only when no resolver answers. Whitelisted paths get the same check.
   A request bound for a servlet other than a `DispatcherServlet` (read from the request's
   `HttpServletMapping` and the `ServletRegistration`) bypasses the matrix: its routes are unknown to the
   mappings and would all be false 404s.
2. **405 second, ONE responder, no `Allow`.** A claimed path whose declared methods do not include the
   request method (HEAD counts as GET; a method-less mapping accepts everything) — the known-but-unimplemented
   case AND the unknown-name case — answers `405` through the same resolvers with
   `HttpRequestMethodNotSupportedException(method)` constructed **without** supported methods, so neither
   Spring's `DefaultHandlerExceptionResolver` nor a `ResponseEntityExceptionHandler` can derive an `Allow`.
   To own the unknown-name case the library registers an `HttpFirewall` bean (`StrictHttpFirewall`,
   `setUnsafeAllowAnyHttpMethod(true)`, `@ConditionalOnMissingBean`); no `RequestRejectedHandler` is
   needed, because with the method check off the firewall never rejects a method name and everything else
   it guards stays as it is. `MethodNotAllowedAccessDeniedHandler` is REPLACED. The 3.0.0 claim of a
   whitelisted-path `501` was wrong: `FrameworkServlet.service` routes every non-standard method to
   `processRequest`, so Spring answered its own `405` (with `Allow`) there — now the library answers first.
3. **401 / 403** for a claimed path + implemented method: the bearer validation and the role rules of
   3.0.0, unchanged. **Plain `OPTIONS` is an existing method** (Spring's `HttpOptionsHandler` answers it
   on every mapped path): it proceeds like any other, so anonymous → `401`; an authenticated caller the
   rules deny gets Spring's `200` + `Allow` from `OptionsAccessDeniedHandler`, which decorates the
   configured (or the default RFC 6750) access-denied handler and reuses the route the filter left in a
   request attribute. Where the rules permit the path Spring answers natively; `OPTIONS` the application
   maps itself is left to the application.
4. **Configuration:** `unmatched-method-response` (3.0.0) is RETIRED — the matrix is not configurable —
   and `RetiredPropertyGuard` fails startup if it is still set on either section, because Boot would
   otherwise ignore the lost `deny` opt-out silently. `secure-endpoints` semantics unchanged for mapped
   paths; the blacklist is an ordinary rule (unmapped → 404, unimplemented method → 405), so
   `BlacklistDecision` / `ReactiveBlacklistDenial` are gone and `denyAll()` is back. The management port's
   chain follows the same matrix, from the child context's mappings, rendered through the child's
   `handlerExceptionResolver` — Boot's composite, which walks up to the parent's resolvers, so the
   application's advice renders there too.

### 3.2 Reactive stack (`ReactiveHttpStatusMatrixFilter`, `ReactiveSupportedMethodsResolver`)

Same matrix, `addFilterBefore(…, SecurityWebFiltersOrder.AUTHENTICATION)`; the resolver consults every
WebFlux `HandlerMapping` in `DispatcherHandler` order through a `ServerWebExchangeDecorator` with its own
attribute map, a `ResourceWebHandler` claiming the path only when its resource resolves (GET/HEAD, the
set it keeps private), and the answers are raised as the exceptions WebFlux raises natively —
`ResponseStatusException(NOT_FOUND)` (what `DispatcherHandler.createNotFoundError` raises) and
`MethodNotAllowedException(method, null)` — into the application's `WebExceptionHandler`s; an error
signal from inside the security chain reaches them exactly as one from the dispatcher would. The reactive
stack has its own firewall (`StrictServerWebExchangeFirewall`, picked up by every `WebFilterChainProxy`
including the management child's), so a `ServerWebExchangeFirewall` bean with any method name allowed is
registered too. `OptionsServerAccessDeniedHandler` is the OPTIONS twin. DNMS ships no reactive service
today; the reactive half keeps parity because the library promises it.

### 3.3 What is NOT the matrix's

- A CORS pre-flight, where CORS is configured: Spring's `CorsFilter` (servlet, always installed) or the
  `CorsWebFilter` (reactive, with a `CorsConfigurationSource` bean) answers it before the matrix runs.
  Where it is not configured, a pre-flight is a plain `OPTIONS` to the matrix.
- `TRACE`: Tomcat refuses it before any filter, with an `Allow` of its own.
- A request whose mappings cannot be consulted (a context still starting, a lookup failure): left to the
  access rules, never answered from a guess — the resolvers return "unresolvable", distinct from "not
  served".

## 4. Tests — the matrix, table-driven, one class per stack

Rows × callers × paths × methods, every cell asserting **status**, **body origin** (a marker resolver in the test app;
never Boot's default JSON) and **no `Allow` on any 405**:

- callers: anonymous; a valid token with the rule's role; a valid token without it.
- paths: a mapped GET-only path; a mapped path with several methods; an UNMAPPED path; a whitelisted (`ALLOW`) path;
  an unmapped path under a whitelisted prefix; a path variable containing `/` that falls off the route table.
- methods: GET, POST, PATCH (unimplemented), PROPFIND and BREW (unknown names), OPTIONS.
- TRACE is the container's (Tomcat refuses it before the filters) — asserted only as "not 2xx".

Existing 3.0.0 tests that pin `Allow` or the anonymous-401-on-unimplemented-method are rewritten to the matrix, not
deleted silently (each change named in the PR). As built: `HttpStatusMatrixCells` is the table (main-port and
management-port rows), `ServletHttpStatusMatrixIT` / `ReactiveHttpStatusMatrixIT` run it through a real Tomcat / Netty,
`ManagementHttpStatusMatrix{Servlet,Reactive}IT` on the management port (the servlet one keeps 3.0.0's leak probe: a
mapping named only in the main context must answer 404 there, not 405). The body origin is a marker header the test
application's own renderers set (`GlobalExceptionHandler.handleExceptionInternal`, `ReactiveErrorRenderer`). The test
application gained a functional route (`/fn`) and a static resource (`/probe.txt`) for the non-annotation rows.

## 5. Release and propagation

3.1.0 (MINOR; CHANGELOG headlines the BREAKING cells) → `opentmf-versions` 2.1.26 pins it → `dnms-service-template`
MINOR takes the BOM + its own contract test (draft PR #57 there, rebased to this table: every `Allow` assertion removed,
the 404-for-unmapped-path cases added anonymous AND authenticated) → every DNMS service at its next cut (template
first). Acceptance per service pin: the four matrix probes through the ingress (unknown path → 404 anonymous AND with a
token; PATCH on a GET-only path → 405 without `Allow`; GET without token → 401; GET with a role-less token → 403).

## 6. What implementation changed (2026-09-15)

Against the plan as first written; each item verified from the 7.0.9 / 7.1.1 sources before being acted on.

1. **`HandlerMappingIntrospector` is not a method-agnostic existence check, and cannot be one.**
   `getMatchableHandlerMapping` calls each mapping's `getHandler`, which throws
   `HttpRequestMethodNotSupportedException` on a path-yes-method-no — and Boot's default resource handler on
   `/**` would have made "any handler for the path" true for every path, so no request could ever have been
   404. §3.1 now describes what was built instead: all `HandlerMapping` beans in dispatch order, annotation
   mappings via their infos, the rest via `getHandler` on an attribute-isolated probe, and a resource handler
   claiming the path only when the resource resolves (`ResourceHandlerUtils.normalizeInputPath` +
   `shouldIgnoreInputPath`, then the handler's own resolvers — Spring's `DefaultResourceResolverChain` is
   package-private, so the library carries a line-for-line mirror).
2. **Plain `OPTIONS` follows rows 3–4, not row 2** (ruling relayed 2026-09-15): anonymous → 401, authenticated
   → Spring's 200 + `Allow`. The first draft answered 200 + `Allow` for everyone before authentication; that
   was the one cell where an anonymous caller would have learned the method set, which the matrix does not
   grant. The `Allow` ban is for 405.
3. **The blacklist is an ordinary rule** (same ruling): unmapped → 404, unimplemented → 405. 3.0.0's D5
   (uniform 403, `BlacklistDecision`) is superseded, and the type plumbing that carried it is gone.
4. **Pre-flights are plain `OPTIONS` to the matrix** (same ruling). The first draft bypassed every pre-flight;
   with CORS configured Spring's own filter already precedes the matrix, and without it the pre-flight has
   no better answer than the matrix's.
5. **The reactive firewall.** The plan named only the servlet `HttpFirewall`; Spring Security 7's
   `WebFilterChainProxy` has a `StrictServerWebExchangeFirewall` of its own, picked up from an
   `ObjectProvider<ServerWebExchangeFirewall>`, and it answered `PROPFIND` with 400 on the reactive matrix
   until the twin bean was registered. Found by the reactive contract test's unknown-name cells.
6. **Requests bound for another servlet bypass the matrix.** Not in the plan: an H2 console, a JAX-RS or SOAP
   engine registered beside the `DispatcherServlet` serves routes the handler mappings cannot see, and every
   one of them would have been a false 404. The filter reads the target servlet from the request's
   `HttpServletMapping` and the `ServletRegistration`, assuming Spring MVC when the container gives no
   mapping information (MockMvc).
7. **"Unresolvable" is distinct from "not served".** A lookup that fails must leave the request to the access
   rules (the 3.0.0 answer), never turn it into a 404 the mappings never said; the resolvers return an
   `Optional`, empty on failure.
8. **The retired property fails startup.** Boot ignores an unknown property silently, and `deny` was an
   opt-out chosen for non-disclosure; losing it without a word was the wrong outcome. `RetiredPropertyGuard`
   sits beside the 3.0.0 case guard in `AccessRuleBindingAutoConfiguration`.
9. **The "body is the application's" promise has a stated edge.** The library hands the native exceptions to
   the application's resolvers exactly as the dispatcher does. An application with no error rendering of its
   own gets Spring's `DefaultHandlerExceptionResolver` → `sendError` → the container's error page, which in a
   Boot application is Boot's default JSON — the same thing it gets natively today for a permitted path.
   Every DNMS service renders these exceptions through its TMF-`Error` advice, so the promise holds where it
   matters; the README says so plainly.
10. **The 3.0.0 "whitelisted path + unknown method → 501" claim was wrong** — `FrameworkServlet.service`
    routes any non-standard method to `processRequest` — and is corrected in §2's spirit by §3.1.
11. **One unexplained observation, recorded rather than smoothed over.** In the first full `clean verify`
    (right after the Keycloak image pull, ~200 s into the JVM) `ServletMultiIssuerIT`'s context answered
    404 for `/car` and `/car/{name}` on every request: the resolver found no claim, and the application's
    advice did not render the exception either (Spring's default resolver did). Six later full runs and
    four isolated loops never reproduced it. The obvious theory — the `DispatcherServlet` initialising
    lazily on the first request, after the filter — was tested and disproven: `ServletFirstRequestIT`
    pins that the very first request of a fresh context on a mapped path is served (the resolver reads
    the `HandlerMapping` beans, which exist since refresh, and Tomcat initialises the servlet before the
    filter chain runs anyway). The resolver now traces every mapping's claim per request, so a recurrence
    is diagnosable; the field check is the four matrix probes on every service pin.
