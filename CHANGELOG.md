# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

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
