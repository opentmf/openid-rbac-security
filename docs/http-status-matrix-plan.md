# The HTTP-status matrix — implementation plan (3.1.0)

| | |
|---|---|
| **Status** | Planned — to be implemented on `feat/http-status-matrix` |
| **Target** | **3.1.0** (Gökhan's ruling, 2026-09-15; BREAKING for anyone relying on 401/403 for unknown paths or on the `Allow` header of a 405 — headlined in the CHANGELOG) |
| **Written** | 2026-09-15, against released 3.0.0 (`docs/http-method-semantics-plan.md` is the 3.0.0 plan this one supersedes in part) |
| **Verified against** | the same Spring Security 7.1.x / Spring Framework 7.0.x the 3.0.0 plan cites — re-resolve with its §0 recipe before implementing |
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

1. **404 first.** Before authentication and before the ACL, ask Spring MVC's `HandlerMappingIntrospector` (the bean
   Spring Security's own `MvcRequestMatcher` uses) whether ANY handler is mapped for the request path, method-agnostic.
   None → answer 404 through the application's `HandlerExceptionResolver` with a `NoHandlerFoundException`
   (`Content-Length: 0` when the application has no resolver) and stop. Whitelisted (`ALLOW`) paths are subject to the
   same check — a whitelisted prefix with no handler is still 404.
2. **405 second, ONE responder, no `Allow`.** A mapped path whose handler does not implement the request method —
   the known-but-unimplemented case (today's `ServletSupportedMethodsResolver` knows the set) AND the unknown-name
   case — answers 405 with the application body via `HttpRequestMethodNotSupportedException(method, allowed)` through
   the resolver. To own the unknown-name case the library registers the `HttpFirewall` (`StrictHttpFirewall` with
   `setUnsafeAllowAnyHttpMethod(true)`) and a `RequestRejectedHandler` so the firewall's 400 never answers a method
   name; everything else the firewall guards (path traversal, encoded separators) stays as it is. The responder sits
   before the servlet for every path, so the whitelisted-path 501 disappears too.
   `MethodNotAllowedAccessDeniedHandler` is REPLACED: no `Allow`, no anonymous → 401 special case.
3. **401 / 403** for mapped path + implemented method: the bearer validation and the role rules of 3.0.0, unchanged.
4. **Configuration:** `unmatched-method-response` (3.0.0) is RETIRED — the matrix is not configurable. `secure-endpoints`
   semantics unchanged for mapped paths. The management port's chain follows the same matrix.

### 3.2 Reactive stack (`MethodNotAllowedServerAccessDeniedHandler`, `ReactiveSupportedMethodsResolver`)

Same matrix; the 404 check asks the WebFlux `HandlerMapping`s (`RequestMappingHandlerMapping` + the resource/router
mappings) for any handler on the path; the 405 responder renders through the application's `WebExceptionHandler`
(`MethodNotAllowedException` without allowed methods → no `Allow`). DNMS ships no reactive service today; the reactive
half keeps parity because the library promises it.

## 4. Tests — the matrix, table-driven, one class per stack

Rows × callers × paths × methods, every cell asserting **status**, **body origin** (a marker resolver in the test app;
never Boot's default JSON) and **no `Allow` on any 405**:

- callers: anonymous; a valid token with the rule's role; a valid token without it.
- paths: a mapped GET-only path; a mapped path with several methods; an UNMAPPED path; a whitelisted (`ALLOW`) path;
  an unmapped path under a whitelisted prefix; a path variable containing `/` that falls off the route table.
- methods: GET, POST, PATCH (unimplemented), PROPFIND and BREW (unknown names), OPTIONS.
- TRACE is the container's (Tomcat refuses it before the filters) — asserted only as "not 2xx".

Existing 3.0.0 tests that pin `Allow` or the anonymous-401-on-unimplemented-method are rewritten to the matrix, not
deleted silently (each change named in the PR).

## 5. Release and propagation

3.1.0 (MINOR; CHANGELOG headlines the BREAKING cells) → `opentmf-versions` 2.1.26 pins it → `dnms-service-template`
MINOR takes the BOM + its own contract test (draft PR #57 there, rebased to this table: every `Allow` assertion removed,
the 404-for-unmapped-path cases added anonymous AND authenticated) → every DNMS service at its next cut (template
first). Acceptance per service pin: the four matrix probes through the ingress (unknown path → 404 anonymous AND with a
token; PATCH on a GET-only path → 405 without `Allow`; GET without token → 401; GET with a role-less token → 403).
