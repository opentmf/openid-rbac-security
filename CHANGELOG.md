# Changelog

All notable changes to this project will be documented in this file.

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
