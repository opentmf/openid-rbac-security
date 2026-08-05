# Changelog

All notable changes to this project will be documented in this file.

## [2.3.0] - 2026-08-05

### Added
- **Multi-issuer resource-server support.** A service can now validate tokens from several identity providers at once — for example Entra ID for user-driven calls and Keycloak for service-to-service calls on the same endpoints — via the new `opentmf.security.issuers` list. Each entry declares its own `issuer`, `jwk-set-uri`, claim mapping and optional audience restriction. **Consumers that do not configure `issuers` see zero behavior change**: the existing `jwk-set-uri` and claim properties keep working exactly as before, including the classpath/file JWK set support, and single-issuer mode continues not to check the `iss` claim.
- Incoming tokens are routed to the entry whose `issuer` matches their `iss` claim, and that entry's decoder validates signature, issuer, expiry and audience. A token whose issuer matches no entry — or that carries no `iss` at all — is rejected with `401 invalid_token`; there is deliberately no fallback issuer.
- Per-issuer claim mapping normalizes each provider's token shape onto the same internal role vocabulary, so `secure-endpoints`, `whitelist`, `blacklist` and `other-endpoints` are written once and never fork per provider. An entry inherits `user-claim`, `fallback-user-claims` and `authorities-claim` from the top-level properties unless it declares its own, so the common vocabulary is configured once and only the deviating issuer overrides it.
- Optional per-issuer `audiences`. When set, a token is rejected unless its `aud` claim contains one of the listed values. Recommended for providers that mint tokens for many applications from a single tenant (Entra in particular), where issuer validation alone would accept a token issued to a different application of the same tenant. Empty by default, so enabling it is an explicit decision and requires no change in calling services.
- The `JwtDecoder` / `ReactiveJwtDecoder` bean routes by issuer in multi-issuer mode, so `JwtService` and any consumer decoding tokens outside the filter chain keep working across every trusted issuer rather than being pinned to one.
- The management-port chain trusts the same set of issuers as the main port on both stacks, since a scraper's JWT may legitimately come from either provider.
- Boot-time validation of the trust declaration: configuring both `jwk-set-uri` and `issuers`, or neither, fails startup with a named error, as do a duplicate `issuer` value (routing would be ambiguous) or a duplicate `name`. Each entry requires `issuer` and `jwk-set-uri`.
- README gained a "Multiple trusted issuers" section covering the dual-issuer configuration, the normalization principle, token routing, audience-validation rollout, and the Entra pitfalls that bite in the field (tenant- and version-specific issuer values, App Roles over truncating group claims, `oid` as the stable principal).

### Changed
- Upgraded to Spring Boot 4.1.0 (from 4.0.6), which brings Spring Security 7.1.0; Spring Framework stays at 7.0.8. The library imports `spring-boot-dependencies` as a BOM rather than inheriting the starter parent, so a consumer's own dependency management still wins — consumers on Boot 4.0 keep their resolved versions and are not forced to upgrade in lockstep. No API this library calls was deprecated or removed in the move.
- Build-only and test-only tooling bumps with no effect on the published artifact: JaCoCo 0.8.15, Surefire/Failsafe 3.5.6, Enforcer 3.6.3, sonar-maven-plugin 5.7.0.6970, testcontainers-keycloak 4.3.1 (the Keycloak image the integration tests run against stays pinned at 26.6).
- `opentmf.security.jwk-set-uri` is no longer annotated `@NotNull` on its own; the requirement moved to a cross-field rule stating that exactly one of `jwk-set-uri` or `issuers` must be configured. A configuration that declares neither still fails to boot, with a clearer message.
- The custom 401/403 handler beans introduced in 2.2.0 continue to apply unchanged in multi-issuer mode, where token validation runs through an authentication-manager resolver rather than the `jwt()` configurer. Covered by regression tests.

### Notes
- Spring Security 7.1 normalizes `JwtAuthenticationToken.getName()` to return `""` instead of `null` when no principal name was supplied. This library only supplies `null` in the degenerate case where a token carries neither the configured `user-claim`, nor any `fallback-user-claims`, nor a `sub` — which it already logs a `WARN` for. Behavior is otherwise unchanged, and no configuration needs revisiting.

## [2.2.0] - 2026-07-30

### Added
- **Pluggable 401/403 response handlers for the main port.** Consumers can now take over the rendering of authentication (401) and URL-authorization (403) failures, which are decided in the security filter chain before the `DispatcherServlet` / `DispatcherHandler` and therefore never reach a `@RestControllerAdvice`. The switch is bean presence — no new configuration properties. Servlet consumers define `AuthenticationEntryPoint` and/or `AccessDeniedHandler` beans; reactive consumers define `ServerAuthenticationEntryPoint` and/or `ServerAccessDeniedHandler` beans. **Consumers that define no such beans see zero behavior change** — the RFC 6750 defaults (status + `WWW-Authenticate` header, empty body) remain exactly as before.
- A supplied handler is applied at both relevant points of the chain: the bearer-token path (invalid/expired/malformed tokens, insufficient scope) and the exception-translation path (no token on a protected URL, role-based denials). Each handler is independent; defining only one of the two is supported.
- If multiple candidate beans of one handler type exist, the library refuses to guess: it logs a `WARN` naming all candidates and keeps the Spring Security default for that handler. Marking one candidate `@Primary` resolves the ambiguity.
- README gained a "Customizing 401/403 responses" section with the plain-beans recipe, the per-stack "one place for all error rendering" recipes (servlet: delegate to `handlerExceptionResolver`; reactive: shared renderer component, including why the `Mono.error` delegate variant is a 500-producing trap), and a matrix of which failure takes which path.
- Method-security (`@PreAuthorize`) denials keep flowing to consumer advice unchanged, and the management port deliberately keeps the RFC 6750 defaults — custom handlers apply to the main port only.

### Changed
- `ReactiveResourceRetriever.getKeys(SignedJWT)` is now `getKeys()` — the parameter was unused
  (the retriever always returns the full JWK set from the configured resource; key selection
  happens in the decoder). Only relevant to consumers calling this internal wiring utility
  directly, which the library never required.

### Fixed
- **Servlet management-port security (introduced in 2.1.0) was ineffective.** On the servlet stack, Spring Boot's `ServletManagementChildContextConfiguration` exposes the *parent* context's `springSecurityFilterChain` inside the management child context, overriding the child's own `@EnableWebSecurity` setup — so the management `SecurityFilterChain` this library registered in the child context was built but never consulted, and the management port was actually governed by the main-port rules (with the default catch-all `deny`, all actuator endpoints — including `/actuator/health` — required authorization and probes would receive 401 regardless of the `opentmf.security.management.*` configuration). The management chain is now registered in the main context, matched by the request's local port (captured from the management server's `WebServerInitializedEvent`, so random ports work), at highest precedence. Servlet consumers with a separate management port now get the behavior documented in 2.1.0: the `opentmf.security.management.*` block (or its defaults) genuinely governs the management port. The reactive stack was not affected — its child context builds and uses its own `SecurityWebFilterChain`.
- The defect was masked in this library's own integration tests by the test application's component scan leaking the management chain into the main context; the test application now excludes `@ManagementContextConfiguration` classes from scanning, and the management ITs assert the enforced behavior for real.

## [2.1.0] - 2026-04-24

### Changed
- **Behavior change for consumers with `management.server.port` set to a value different from `server.port`.** Actuator endpoints on the management port that were previously reachable anonymously now require an authenticated JWT, except for the default `whitelist` (`/actuator/health`, `/actuator/health/**`, `/actuator/info`). Consumers that scrape `/actuator/prometheus`, `/actuator/metrics`, `/actuator/loggers`, or any other non-default management endpoint without authentication must either add those paths to the new `opentmf.security.management.whitelist` property, or reconfigure their scraper to present a JWT. Consumers who do not set `management.server.port`, or who set it equal to `server.port`, are unaffected (the main-port filter chain already governed those endpoints).

### Added
- **`opentmf.security.other-endpoints` for the main port.** New top-level enum property controlling the catch-all policy for requests not matched by `blacklist`, `whitelist`, `allowed-endpoints`, or `secure-endpoints`. Values: `allow` (permit anonymously), `deny`, `authenticated` (require any valid JWT). Defaults to `deny`, preserving the historical hard-coded behavior — consumers who never set this property see no functional difference.
- **JWT-authenticated management port.** When consumers set `management.server.port` to a value different from `server.port`, the library now registers a second `SecurityFilterChain` (servlet) / `SecurityWebFilterChain` (reactive) in the management child `ApplicationContext`. The chain reuses the existing `JwtDecoder` and authorities converter from the parent context, so no JWT wiring is duplicated.
- New configuration section `opentmf.security.management`. Property names mirror the main-port section so configuration knowledge transfers directly:
  - `blacklist` (paths denied for all HTTP methods).
  - `whitelist` (defaults to `/actuator/health`, `/actuator/health/**`, `/actuator/info` — commonly probed by infrastructure without auth).
  - `allowed-endpoints` (method-specific paths that bypass authentication).
  - `secure-endpoints` (role-gated method-specific paths).
  - `other-endpoints` (catch-all policy; same enum as the main port, but defaults to `authenticated` instead of `deny`). The default differs because actuator endpoints are well-known and most consumers want every exposed endpoint reachable with any valid JWT without enumerating each one. Set to `deny` for main-port-style symmetry.
- Registered via a new `META-INF/spring/org.springframework.boot.actuate.autoconfigure.web.ManagementContextConfiguration.imports` file and gated by `OnSeparateManagementPortCondition`, so the management auto-configs only load into the management child context and only when the two ports genuinely differ.
- Startup `WARN` logs for two misconfiguration cases, gated on actuator being on the classpath:
  - `opentmf.security.management.*` configured but ports coincide (block will be ignored — consumer probably expected otherwise).
  - Ports differ but no `management` block configured (library defaults govern — consumer who scrapes `/actuator/prometheus` etc. without a JWT likely needs to add it to `whitelist`).
- `spring-boot-actuator-autoconfigure` declared as an optional dependency so the new code compiles; consumers must bring `spring-boot-starter-actuator` themselves to activate the management-port behavior.

### Notes
- Spring Boot's own `management.endpoint.env.show-values: when_authorized` (and `show-components`) now works as intended when this library is on the classpath — previously the check always returned "unauthorized" on a separate management port because no filter populated the `SecurityContext`.
- Source and binary compatibility preserved. No public API removed; only additions. Consumers who never set `management.server.port` see no functional difference.

## [2.0.0] - 2026-03-24

### Changed
- **Breaking:** Upgraded to Spring Boot 4.0.4 (from 3.5.9), bringing Spring Framework 7.x, Spring Security 7.0, Jackson 3, and Testcontainers 2.0.
- Replaced `spring-boot-starter-parent` with `spring-boot-dependencies` BOM in `<dependencyManagement>`, allowing consumers to use their own parent POM.
- Renamed starter dependencies to match Boot 4 conventions:
  - `spring-boot-starter-web` -> `spring-boot-starter-webmvc`
  - `spring-boot-starter-oauth2-resource-server` -> `spring-boot-starter-security-oauth2-resource-server`
  - `spring-boot-starter-test` / `spring-security-test` -> `spring-boot-starter-webmvc-test`, `spring-boot-starter-webflux-test`, `spring-boot-starter-security-test`
- Migrated Jackson 2 annotations to Jackson 3 (`tools.jackson.databind`).
- Made auto-configuration `@Bean` methods package-private per Boot 4 convention.
- Removed `@AutoConfigureAfter(WebClientAutoConfiguration.class)` from `ServletSecurityAutoConfiguration` (class relocated to a separate module in Boot 4).
- Updated `@AutoConfigureMockMvc` import to new Boot 4 package (`org.springframework.boot.webmvc.test.autoconfigure`).
- Testcontainers artifact renamed from `junit-jupiter` to `testcontainers-junit-jupiter` (TC 2.0).
- Added `-parameters` compiler flag (required by Spring Framework 7).
- Bumped minimum Maven version from 3.6.3 to 3.9.0.

## [1.1.1] - 2025-06-15

### Added
- `fallback-user-claims` configuration property to support fallback claim extraction when the primary `user-claim` is not present in the JWT token. This enables support for both password grant tokens (with user claims like `email`) and client_credentials grant tokens (with service claims like `client_id`, `azp`, `appid`). The fallback mechanism tries claims in order and falls back to JWT `sub` if none are found.

## [1.1.0] - 2025-05-01

### Changed
- Initial Open Source Release, replacing `pia` with `opentmf`.

## [1.0.9]

### Fixed
- Fixed cors headers configuration to obey the application configuration.

## [1.0.8]

### Fixed
- Fixed `jwk-set-uri` local file retrievals for enabling easier integration tests.

## [1.0.7]

### Fixed
- Fixed conditional typo on `configureWhitelist` in `ServletSecurityAutoConfiguration`.

## [1.0.6]

### Changed
- Both `whitelist` and `blacklist` have been made optional.

## [1.0.5]

### Fixed
- Fixed the support for handling deeper levels for `authorities-claim`.

## [1.0.4]

### Fixed
- Support deeper levels for `authorities-claim`.

## [1.0.3]

### Changed
- Removed blocking hardcoded swagger endpoints.

### Added
- New configuration property `blacklist` that allows specifying endpoints to be blocked.

## [1.0.2]

### Changed
- **Breaking:** Configuration prefix is now `pia.security`.

## [1.0.1]

### Added
- Started including source code in releases.
- Started allowing local file for `jwk-set-uri`.

## [1.0.0]

### Added
- Initial revision.
