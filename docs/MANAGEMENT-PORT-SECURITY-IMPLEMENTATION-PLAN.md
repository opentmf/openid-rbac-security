# Management-Port JWT Security — Implementation Plan

**Target repo:** `openid-rbac-security`
**Target version:** next minor (suggested `2.1.0`, or a new SNAPSHOT above current `2.0.1-SNAPSHOT`)
**Written:** 2026-04-24

---

## 1. Why

When consumers set Spring Boot's `management.server.port` different from `server.port`
(to isolate actuator endpoints on an internal-network port, firewalled away from
public ingress), the separate management `ApplicationContext` does **not**
inherit the main port's `SecurityFilterChain`. Today this library registers
exactly one `SecurityFilterChain` bean — scoped to the main context — so the
management connector boots with **no JWT parsing, no authentication, no
`SecurityContextHolder` population**.

Two concrete consequences downstream:

1. **Unauthenticated access to every `/actuator/**` endpoint** on the management
   port. `/actuator/health` and `/actuator/info` are probably fine for internal
   infrastructure to probe; `/actuator/metrics`, `/actuator/loggers`,
   `/actuator/httpexchanges` etc. are not.
2. **`management.endpoint.env.show-values: when_authorized` is inert.** The
   contributor asks `SecurityContextHolder.getContext().getAuthentication()` for
   authorities; with no filter populating the context, the answer is always
   "unauthorized", and every value is redacted to `******` even for a legitimate
   admin-role JWT. Consumers who want admin-gated env values have no path to
   unredact them.

This plan adds a second filter chain, scoped to the management context, that
reuses the library's existing JWT decoder + principal/authorities converters.
Consumers who set `management.server.port` get JWT-authenticated `/actuator/**`
automatically; everyone else is unaffected.

Primary downstream consumer motivating this work: the integration-adapter
generator suite (`integration-adapter-generator-suite` 1.0.2+), which moved
actuator to its own port for context-path isolation and is blocked on RBAC
enforcement without this.

---

## 2. Scope

### In scope (first pass)

- **Servlet stack:** register a second `SecurityFilterChain` in the management
  child context. JWT-authenticated via the existing decoder + converter chain.
- **Reactive stack:** same for `SecurityWebFilterChain`, preserving the dual-stack
  design.
- **Anonymous-path default list:** `/actuator/health`, `/actuator/health/**`,
  `/actuator/info` — reachable without a JWT so kubelet probes / LB health
  checks / dashboards work. Everything else on the management port requires an
  authenticated JWT.
- **Property-driven customization:** consumers can override the anonymous-path
  list and declare role-gated management endpoints (`secure-endpoints` style,
  mirroring the main-port model).
- Testcontainers-backed integration tests for both stacks.
- CHANGELOG, README, version bump.

### Out of scope (explicitly)

- Changing the main-port filter chain.
- Dynamic registration of new actuator endpoints (the property list is static
  per application startup; good enough).
- CORS, CSRF, or session-management differences between main and management
  ports. Management stays stateless like the main port.
- Per-endpoint redaction logic (`show-values`, `show-components`). Those are
  Spring Boot's own endpoint properties; this library stays out of them.
- Non-Spring-Boot-Actuator management-port scenarios (custom management
  connectors). Uncommon and adds complexity for no gain.

---

## 3. Current state — what to preserve

Code locations the plan will touch (and those it won't):

| File | Role today | After this work |
|---|---|---|
| `src/main/java/org/opentmf/security/config/ServletSecurityAutoConfiguration.java` | Main-port servlet `SecurityFilterChain` | **Unchanged.** |
| `src/main/java/org/opentmf/security/config/ReactiveSecurityAutoConfiguration.java` | Main-port reactive `SecurityWebFilterChain` | **Unchanged.** |
| `src/main/java/org/opentmf/security/config/ServletJwtAutoConfiguration.java` | `JwtDecoder` bean | **Unchanged.** Child context inherits via parent-first lookup. |
| `src/main/java/org/opentmf/security/config/ReactiveJwtAutoConfiguration.java` | `ReactiveJwtDecoder` bean | **Unchanged.** Same reason. |
| `src/main/java/org/opentmf/security/jwt/GrantedAuthoritiesConverter.java` | JWT-claims-to-authorities | **Unchanged.** Reused by the management chain. |
| `src/main/java/org/opentmf/security/jwt/ServletJwtPrincipalConverter.java` | JWT-to-auth-token (servlet) | **Unchanged.** Reused. |
| `src/main/java/org/opentmf/security/jwt/ReactiveJwtPrincipalConverter.java` | JWT-to-auth-token (reactive) | **Unchanged.** Reused. |
| `src/main/java/org/opentmf/security/model/OpenTmfSecurityProperties.java` | `@ConfigurationProperties` under `opentmf.security` | Adds nested `management` section (new inner class + getter). |
| `src/main/resources/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports` | Lists the four existing auto-configs | **Unchanged.** Management auto-configs go in a *different* imports file (see §4.4). |

Classes to add (all new):

- `config/management/ServletManagementSecurityAutoConfiguration.java`
- `config/management/ReactiveManagementSecurityAutoConfiguration.java`
- `model/ManagementSecurityProperties.java` (inner class inside `OpenTmfSecurityProperties`, or standalone — see §4.1)
- `src/main/resources/META-INF/spring/org.springframework.boot.actuate.autoconfigure.web.server.ManagementContextConfiguration.imports`
- Test classes mirroring the existing `BaseServletIT` / `ServletControllerIT` pattern.

All public API on the main-port side stays stable.

---

## 4. Design

### 4.1 Configuration properties

Add a nested `management` section under `opentmf.security`:

```java
// inside OpenTmfSecurityProperties
private @Valid Management management = new Management();

public static class Management {
  /**
   * Paths on the management port served without authentication. Defaults to
   * the three endpoints that infrastructure probes typically hit unauthenticated:
   * /actuator/health, /actuator/health/** (liveness/readiness subpaths),
   * /actuator/info.
   */
  private List<@NotEmpty String> anonymousPaths = new ArrayList<>(List.of(
      "/actuator/health", "/actuator/health/**", "/actuator/info"));

  /**
   * Paths on the management port that require specific authorities. Evaluated
   * after anonymousPaths. Mirrors the main-port `secure-endpoints` model.
   */
  private List<@Valid SecureEndpoint> secureEndpoints = new ArrayList<>();

  /**
   * When true (default), any request on the management port not matched by
   * anonymousPaths or secureEndpoints requires an authenticated JWT. When false,
   * unmatched requests are denied — useful for paranoid setups where the
   * whitelist must be explicit.
   */
  private boolean authenticateByDefault = true;

  // getters/setters
}
```

YAML form:

```yaml
opentmf:
  security:
    jwk-set-uri: https://keycloak.example.com/realms/x/protocol/openid-connect/certs
    # ... existing main-port config ...
    management:
      anonymous-paths:
        - /actuator/health
        - /actuator/health/**
        - /actuator/info
      secure-endpoints:
        - method: GET
          path: /actuator/env
          roles: [admin]
        - method: GET
          path: /actuator/env/**
          roles: [admin]
      authenticate-by-default: true
```

If consumers don't supply a `management` block at all, the defaults above
apply. Existing consumers who set `management.server.port` today get safe
defaults (three anonymous probe paths, JWT required for everything else, no
vendor-specific RBAC).

### 4.2 Servlet auto-configuration

`src/main/java/org/opentmf/security/config/management/ServletManagementSecurityAutoConfiguration.java`:

```java
@ManagementContextConfiguration(ManagementContextType.CHILD)
@Conditional(OnSeparateManagementPortCondition.class)
@ConditionalOnClass({SecurityFilterChain.class, HttpSecurity.class})
@EnableWebSecurity
@EnableConfigurationProperties(OpenTmfSecurityProperties.class)
@Slf4j
public class ServletManagementSecurityAutoConfiguration {

  private final OpenTmfSecurityProperties props;

  public ServletManagementSecurityAutoConfiguration(OpenTmfSecurityProperties props) {
    this.props = props;
  }

  @Bean
  SecurityFilterChain managementSecurityFilterChain(
      HttpSecurity http,
      JwtDecoder jwtDecoder,                                         // parent-context bean
      Converter<Jwt, AbstractAuthenticationToken> jwtAuthConverter   // parent-context bean
  ) throws Exception {
    return http
        .sessionManagement(s -> s.sessionCreationPolicy(STATELESS))
        .csrf(CsrfConfigurer::disable)
        .formLogin(FormLoginConfigurer::disable)
        .httpBasic(HttpBasicConfigurer::disable)
        .logout(LogoutConfigurer::disable)
        .authorizeHttpRequests(this::applyManagementAuthorization)
        .oauth2ResourceServer(o -> o
            .jwt(j -> j.decoder(jwtDecoder).jwtAuthenticationConverter(jwtAuthConverter)))
        .build();
  }

  private void applyManagementAuthorization(
      AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry r) {
    var m = props.getManagement();
    m.getAnonymousPaths().forEach(p -> r.requestMatchers(p).permitAll());
    m.getSecureEndpoints().forEach(se ->
        r.requestMatchers(se.getMethod(), se.getPath()).hasAnyAuthority(se.getRoles()));
    if (m.isAuthenticateByDefault()) {
      r.anyRequest().authenticated();
    } else {
      r.anyRequest().denyAll();
    }
  }
}
```

Key mechanics:

- **`@ManagementContextConfiguration(CHILD)`** — registers this configuration
  into the separate child `ApplicationContext` Spring Boot creates for the
  management connector. Discovered via
  `META-INF/spring/org.springframework.boot.actuate.autoconfigure.web.server.ManagementContextConfiguration.imports`.
- **`@Conditional(OnSeparateManagementPortCondition.class)`** — only active
  when `management.server.port` is set *and* differs from `server.port`.
  Spring Boot's `ManagementContextType.CHILD` evaluation implicitly agrees
  (it only creates a CHILD context in that same case), so the condition is
  belt-and-suspenders, but having it explicit at the condition level makes
  the intent obvious at code-review time and guards against
  framework-internal-behavior drift. See §4.2.1 for the condition class.
- **Parent-context bean reuse.** `JwtDecoder` and the authority converter are
  injected as `@Bean` parameters. Spring resolves these from the parent
  (application root) context. No JWT parsing is duplicated.
- **Shared properties.** Uses the same `OpenTmfSecurityProperties` instance as
  the main context — the nested `management` section is the new surface.

### 4.2.1 The `OnSeparateManagementPortCondition` class

`src/main/java/org/opentmf/security/config/management/OnSeparateManagementPortCondition.java`:

```java
package org.opentmf.security.config.management;

import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.boot.autoconfigure.condition.SpringBootCondition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;

/**
 * Activates only when {@code management.server.port} is explicitly set to a value
 * different from {@code server.port}. In that case Spring Boot spawns a separate
 * child {@code ApplicationContext} for the management connector, which is where
 * the management-port {@code SecurityFilterChain} needs to live.
 *
 * <p>When {@code management.server.port} is unset, or equal to {@code server.port},
 * actuator shares the main connector and the main {@code SecurityFilterChain}
 * already protects it — so this library's management auto-configuration must stay
 * inert to avoid duplicate filter-chain registration.
 */
public class OnSeparateManagementPortCondition extends SpringBootCondition {

  @Override
  public ConditionOutcome getMatchOutcome(ConditionContext context, AnnotatedTypeMetadata md) {
    var env = context.getEnvironment();
    String managementPort = env.getProperty("management.server.port");
    if (managementPort == null || managementPort.isBlank()) {
      return ConditionOutcome.noMatch("management.server.port is not set");
    }
    String serverPort = env.getProperty("server.port", "8080"); // Spring Boot's default
    if (managementPort.equals(serverPort)) {
      return ConditionOutcome.noMatch(
          "management.server.port (%s) equals server.port (%s); management shares the main connector"
              .formatted(managementPort, serverPort));
    }
    return ConditionOutcome.match(
        "management.server.port (%s) differs from server.port (%s); separate child context active"
            .formatted(managementPort, serverPort));
  }
}
```

Using a `SpringBootCondition` subclass instead of SpEL on `@ConditionalOnExpression`
has two advantages: the outcome message is visible in the `conditions` actuator
report (helps consumers debug why the filter chain didn't activate), and
property resolution handles placeholder chains cleanly without shell-style
string escaping surprises.

### 4.3 Reactive auto-configuration

`config/management/ReactiveManagementSecurityAutoConfiguration.java` mirrors
the servlet version, with the same annotations (including
`@Conditional(OnSeparateManagementPortCondition.class)`) and:

- `@Bean SecurityWebFilterChain managementSecurityWebFilterChain(...)`
- `ServerHttpSecurity` instead of `HttpSecurity`
- `AuthorizeExchangeSpec` instead of `AuthorizationManagerRequestMatcherRegistry`
- Parent-context beans injected: `ReactiveJwtDecoder` and
  `Converter<Jwt, Mono<? extends AbstractAuthenticationToken>>`

The condition class is stack-agnostic — no reactive-specific variant needed.

### 4.4 Discovery via ManagementContextConfiguration.imports

Spring Boot 3+ / 4+ discovers management-context configurations from a separate
imports file:

```
src/main/resources/META-INF/spring/org.springframework.boot.actuate.autoconfigure.web.server.ManagementContextConfiguration.imports
```

Contents:

```
org.opentmf.security.config.management.ServletManagementSecurityAutoConfiguration
org.opentmf.security.config.management.ReactiveManagementSecurityAutoConfiguration
```

The existing
`META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`
stays unchanged — putting these classes there would cause them to load into
the parent context too, defeating the point.

### 4.5 Interaction with endpoint-level redaction

Consumer-side example (in the adapter's `application.yaml`):

```yaml
management:
  endpoint:
    env:
      show-values: when_authorized
      roles: [admin]
```

With this library's change:
- Request arrives on management port with admin JWT.
- `ServletManagementSecurityAutoConfiguration` filter chain runs. JWT decoded,
  `SecurityContextHolder` populated with authorities including `admin`.
- `EnvironmentEndpoint` serializes. `show-values: when_authorized` checks the
  `SecurityContext` for `admin` authority → present → values unredacted.

Request without JWT hits `/actuator/env`:
- Not in `anonymousPaths`, not in `secureEndpoints` (unless consumer added it).
- `authenticateByDefault: true` → 401 Unauthorized at the filter chain level.
- Never reaches the endpoint.

Request with a JWT but without admin role:
- Authenticated. Reaches the endpoint.
- `EnvironmentEndpoint` sees no `admin` authority → values redacted.
- 200 OK with redacted payload.

This is exactly the posture consumers want and can't get today.

### 4.6 Startup configuration warnings

Two misconfiguration scenarios are legitimate operator smells — catching them
with a startup `WARN` saves debugging time:

| # | Scenario | Smell |
|---|---|---|
| a | Actuator on classpath; `management.server.port` unset or equal to `server.port`; consumer configured a non-default `opentmf.security.management` block. | The management block is being ignored (it only applies in CHILD context). Consumer probably believed their rules were in effect and won't notice until something breaks. |
| b | Actuator on classpath; `management.server.port` set to a value different from `server.port`; consumer did **not** configure a `opentmf.security.management` block (defaults in effect). | Library defaults (3 anonymous paths, everything else requires JWT) govern the management connector. Consumers with `management.endpoints.web.exposure.include=prometheus,metrics,…` might not realize their scrapers now need a JWT. |

Implement via a small always-loaded warner bean, gated only on actuator being
present on the classpath:

`src/main/java/org/opentmf/security/config/management/ManagementSecurityConfigurationWarner.java`:

```java
@Slf4j
@RequiredArgsConstructor
@ConditionalOnClass(name = "org.springframework.boot.actuate.endpoint.annotation.Endpoint")
public class ManagementSecurityConfigurationWarner {

  private static final List<String> DEFAULT_ANONYMOUS_PATHS = List.of(
      "/actuator/health", "/actuator/health/**", "/actuator/info");

  private final Environment environment;
  private final OpenTmfSecurityProperties props;

  @EventListener(ApplicationReadyEvent.class)
  public void checkConfiguration() {
    boolean portsDiffer = portsDiffer();
    boolean managementBlockConfigured = managementBlockConfigured();

    if (!portsDiffer && managementBlockConfigured) {
      log.warn(
          "opentmf.security.management.* is configured, but management.server.port is "
          + "unset or equals server.port. The management block is IGNORED because "
          + "actuator shares the main connector. Use opentmf.security.whitelist, "
          + "secure-endpoints, or allowed-endpoints for /actuator/** paths, or set "
          + "management.server.port to a different port to activate the management block.");
    }

    if (portsDiffer && !managementBlockConfigured) {
      log.warn(
          "management.server.port differs from server.port (actuator on separate port), "
          + "but opentmf.security.management.* is not configured. Library defaults apply: "
          + "anonymous access to /actuator/health, /actuator/health/**, /actuator/info; "
          + "JWT required for every other /actuator/** endpoint. If you expose scrapers "
          + "like /actuator/prometheus or /actuator/metrics (via "
          + "management.endpoints.web.exposure.include), add their paths to "
          + "opentmf.security.management.anonymous-paths or configure your scraper to "
          + "present a valid JWT.");
    }
  }

  private boolean portsDiffer() {
    String mgmt = environment.getProperty("management.server.port");
    if (mgmt == null || mgmt.isBlank()) {
      return false;
    }
    String server = environment.getProperty("server.port", "8080");
    return !mgmt.equals(server);
  }

  private boolean managementBlockConfigured() {
    var m = props.getManagement();
    return !DEFAULT_ANONYMOUS_PATHS.equals(m.getAnonymousPaths())
        || !m.getSecureEndpoints().isEmpty();
  }
}
```

Register it as a `@Bean` in the main `ServletSecurityAutoConfiguration`
(and the reactive counterpart — or, simpler, a new tiny auto-config class
listed in the main `AutoConfiguration.imports` so it loads exactly once
regardless of servlet/reactive stack). The `@ConditionalOnClass` guard ensures
we don't chatter for consumers who don't use actuator at all.

The warner is **intentionally not** scoped to the CHILD context; it needs to
fire in every boot, including SAME-port mode where the CHILD context doesn't
exist. Firing on `ApplicationReadyEvent` (not `ApplicationStartedEvent`)
ensures all property sources are bound by the time we inspect them.

---

## 5. Testing

### 5.1 What to test

- Property binding for the new `management` section (nested in
  `OpenTmfSecurityProperties`).
- Default anonymous paths list is what's documented.
- Unit tests for the authorization application logic (the `apply…Authorization`
  method): anonymous path → permitAll; secure endpoint → `hasAnyAuthority`;
  any remaining → authenticated (or denyAll when flag flipped).
- Unit tests for `OnSeparateManagementPortCondition`: property unset, blank,
  equal to `server.port`, different from `server.port`.
- Unit tests for `ManagementSecurityConfigurationWarner`, capturing logger
  output (e.g. via Logback `ListAppender` or SLF4J test extensions):
  - SAME port + non-default `management` block → case (a) warning fires.
  - CHILD port + default `management` block → case (b) warning fires.
  - SAME port + default block → neither warning.
  - CHILD port + configured block → neither warning.

### 5.2 Integration tests (Testcontainers + @SpringBootTest)

Mirror the existing `BaseServletIT`/`ServletControllerIT` pattern. New test
class `ManagementServletIT`:

```java
@SpringBootTest(
    webEnvironment = WebEnvironment.DEFINED_PORT,
    properties = {
        "server.port=8090",
        "management.server.port=9090",
        "management.endpoints.web.exposure.include=health,info,env,metrics",
        "management.endpoint.env.show-values=when_authorized",
        "management.endpoint.env.roles=admin"
    })
@AutoConfigureMockMvc
class ManagementServletIT extends BaseIT {

  @Test void healthReachableWithoutJwt() { /* GET 9090/actuator/health → 200 */ }
  @Test void infoReachableWithoutJwt() { /* GET 9090/actuator/info → 200 */ }
  @Test void metricsRejectedWithoutJwt() { /* GET 9090/actuator/metrics → 401 */ }
  @Test void metricsAcceptedWithAnyAuthenticatedJwt() { /* → 200 */ }
  @Test void envValuesRedactedForNonAdmin() { /* GET env with user role → 200, values ****** */ }
  @Test void envValuesUnredactedForAdmin() { /* GET env with admin role → 200, real values */ }
  @Test void mainPortUnaffected() { /* GET 8090/your-endpoint → existing behaviour */ }
}
```

Reuse the existing `KeycloakContainer` setup from `ServletControllerIT`. Both
ports (8090 main, 9090 management) live in the same JVM; the JWT is valid
against either as long as the `jwk-set-uri` resolves.

Add a **reactive counterpart** (`ManagementReactiveIT`) using `WebTestClient`,
same scenarios.

### 5.3 Local-JWK-set variant

Add `ManagementServletLocalJwkSetIT` using the file-based JWK pattern
(`classpath:jwks.json`) to match `ServletControllerLocalJwkSetIT`. Faster
feedback for developers running without Docker.

### 5.4 JaCoCo coverage

The repo enforces 90% coverage. New classes should be small and trivially
coverable — the authorization-application method has ~4 branches (anonymous
matched / secure matched / default authenticated / default deny). All hit by
the IT suite listed above. If the ratio slips, add a focused unit test for
`applyManagementAuthorization` using a mocked
`AuthorizationManagerRequestMatcherRegistry`.

---

## 6. Docs

### 6.1 README.md

Add a **"Management-port security"** section after the existing
configuration reference. Cover:

- Why the split (separate `ApplicationContext` → no shared filter chain).
- How to enable (set `management.server.port` — the library reacts).
- Default anonymous paths and why those three are defaults.
- How to add RBAC via `secure-endpoints`.
- How this composes with Spring Boot's endpoint-level redaction
  (`when_authorized` works once this library is active).
- `authenticate-by-default` semantics.

Include a worked YAML snippet — consumers can paste it verbatim.

### 6.2 CHANGELOG.md

New `[2.1.0]` section above `[2.0.0]`:

```markdown
## [2.1.0] - YYYY-MM-DD

### Changed
- **Behavior change for consumers with `management.server.port` set to a value
  different from `server.port`.** Actuator endpoints on the management port
  that were previously reachable anonymously now require an authenticated JWT,
  except for the default `anonymous-paths` list (`/actuator/health`,
  `/actuator/health/**`, `/actuator/info`). Consumers that scrape
  `/actuator/prometheus`, `/actuator/metrics`, `/actuator/loggers`, or any
  other non-default management endpoint without authentication must either
  add those paths to the new `opentmf.security.management.anonymous-paths`
  property, or reconfigure their scraper to present a JWT. Consumers who do
  not set `management.server.port`, or who set it equal to `server.port`, are
  unaffected (the main-port filter chain already governed those endpoints).

### Added
- **JWT-authenticated management port.** When consumers set
  `management.server.port` to a value different from `server.port`, the
  library now registers a second `SecurityFilterChain` (servlet) /
  `SecurityWebFilterChain` (reactive) in the management child
  `ApplicationContext`. The chain reuses the existing `JwtDecoder` and
  authorities converter from the parent context, so no JWT wiring is
  duplicated.
- New configuration section `opentmf.security.management`:
  - `anonymous-paths` (defaults to `/actuator/health`, `/actuator/health/**`,
    `/actuator/info` — commonly probed by infrastructure without auth)
  - `secure-endpoints` (role-gated paths, mirroring the main-port model)
  - `authenticate-by-default` (boolean, default true)
- Registered via a new
  `META-INF/spring/org.springframework.boot.actuate.autoconfigure.web.server.ManagementContextConfiguration.imports`
  file and gated by `OnSeparateManagementPortCondition`, so the management
  auto-configs only load into the management child context and only when the
  two ports genuinely differ.
- Startup `WARN` logs for two misconfiguration cases, gated on actuator being
  on the classpath:
  - `opentmf.security.management.*` configured but ports coincide (block
    will be ignored → consumer probably expected otherwise).
  - Ports differ but no `management` block configured (library defaults
    govern → consumer who scrapes `/actuator/prometheus` etc. without a JWT
    likely needs to add it to `anonymous-paths`).

### Notes
- Spring Boot's own `management.endpoint.env.show-values: when_authorized`
  (and `show-components`) now works as intended when this library is on the
  classpath — previously the check always returned "unauthorized" on a
  separate management port because no filter populated the SecurityContext.
- Source and binary compatibility preserved. No public API removed; only
  additions. Consumers who never set `management.server.port` see no
  functional difference.
```

Follow the existing Keep a Changelog style. Put **Changed** before **Added**
in this section so readers upgrading see the behavior change first.

---

## 7. Step-by-step task list

Each step leaves the build green.

1. **Add `Management` nested class + accessor to `OpenTmfSecurityProperties`.**
   Add a unit test in the existing properties-binding test verifying defaults.

2. **Create `config/management/ServletManagementSecurityAutoConfiguration`.**
   Compile check; no runtime wiring yet (imports file not added).

3. **Create `config/management/ReactiveManagementSecurityAutoConfiguration`.**
   Compile check.

4. **Add the `ManagementContextConfiguration.imports` file** listing both
   auto-configs. Run the existing test suite — it must stay green because
   none of the existing tests set `management.server.port`.

5. **Add `ManagementServletIT`** using the Keycloak container. Assertions per
   §5.2. Verify it fails without the auto-config, passes with it.

6. **Add `ManagementServletLocalJwkSetIT`** (faster feedback).

7. **Add `ManagementReactiveIT`** mirroring the servlet IT with
   `WebTestClient`.

8. **Check JaCoCo coverage** (`mvn verify`). Add focused unit tests for any
   uncovered branches in the new auth-application methods.

9. **README update** — "Management-port security" section.

10. **CHANGELOG entry** under `[2.1.0]` with today's date (at release time).

11. **Version bump** — `pom.xml` to `2.1.0-SNAPSHOT` if not already, and
    `2.1.0` at release.

12. **Manual smoke test from a downstream consumer.** Bump
    `integration-adapter-generator-suite`'s opentmf BOM to the new snapshot,
    regenerate an adapter, verify:
    - `GET http://host:16000/actuator/health` → 200 unauthenticated.
    - `GET http://host:16000/actuator/metrics` without JWT → 401.
    - `GET http://host:16000/actuator/env` with admin JWT → values unredacted.
    - `GET http://host:16000/actuator/env` with user JWT → values redacted
      (`******`).

---

## 8. Deliverables checklist

- [ ] `src/main/java/org/opentmf/security/model/OpenTmfSecurityProperties.java` — new nested `Management` class + accessor.
- [ ] `src/main/java/org/opentmf/security/config/management/OnSeparateManagementPortCondition.java`
- [ ] `src/main/java/org/opentmf/security/config/management/ServletManagementSecurityAutoConfiguration.java`
- [ ] `src/main/java/org/opentmf/security/config/management/ReactiveManagementSecurityAutoConfiguration.java`
- [ ] `src/main/java/org/opentmf/security/config/management/ManagementSecurityConfigurationWarner.java` + bean registration
- [ ] `src/main/resources/META-INF/spring/org.springframework.boot.actuate.autoconfigure.web.server.ManagementContextConfiguration.imports`
- [ ] `src/test/java/.../OnSeparateManagementPortConditionTest.java` (unit tests: unset, blank, equal, different)
- [ ] `src/test/java/.../ManagementSecurityConfigurationWarnerTest.java` (four scenarios, assert on captured log output)
- [ ] `src/test/java/.../ManagementServletIT.java` (Testcontainers)
- [ ] `src/test/java/.../ManagementServletLocalJwkSetIT.java` (file JWK)
- [ ] `src/test/java/.../ManagementReactiveIT.java` (WebTestClient)
- [ ] Unit tests for `applyManagementAuthorization` (coverage-gap fill if needed)
- [ ] `README.md` — new "Management-port security" section
- [ ] `CHANGELOG.md` — `[2.1.0]` entry
- [ ] `pom.xml` version bump
- [ ] `mvn clean verify` green locally (JaCoCo 90%+ preserved)
- [ ] `mvn -P release verify` green (source + javadoc jars build)
- [ ] Downstream smoke test against `integration-adapter-generator-suite`

---

## 9. Risks & open questions

- **Management port without a JwtDecoder bean.** If a consumer somehow configures
  `management.server.port` but their spec provides no
  `opentmf.security.jwk-set-uri`, `JwtDecoder` isn't created, and the new
  management filter chain fails to wire. Behavior: application startup fails
  with a clear `NoSuchBeanDefinitionException`. That's correct — they can't
  have authenticated actuator without a JWT source. Document the requirement.

- **Management port using HTTPS with different cert.** Out of scope here; the
  library's HTTPS posture is handled by Spring Boot's own
  `management.server.ssl.*`. Our filter chain doesn't touch TLS.

- **Custom management context types.** Spring Boot supports `ManagementContextType.SAME`
  (management on the same port). In that mode our new auto-config stays inert
  by two layers: (a) `@ManagementContextConfiguration(CHILD)` means Spring Boot
  only loads it when a CHILD context exists, and (b)
  `OnSeparateManagementPortCondition` explicitly denies the match when
  `management.server.port` is unset or equals `server.port`. On SAME mode, the
  main filter chain already secures actuator. Worth a line in the README.

- **Reactive stack gets less real-world testing.** The opentmf TMF adapter use
  case is servlet-only. Reactive support exists in this library but may get
  thinner production coverage. Keep the reactive IT test suite in parity with
  servlet to catch regressions.

- **Downstream CHANGELOG noise.** Once this ships, the integration adapter
  generator suite's generator-history docs should mention the dependency on
  `opentmf-openid-rbac-security 2.1.0+` for management-port JWT auth. That's
  their problem, not this repo's.

---

## 10. Hand-off notes

When the work lands:

1. Cut a release (`2.1.0` suggested). Bump `opentmf-versions` BOM to reference it.
2. Notify the `integration-adapter-generator-suite` work track. Their
   `[1.0.2]` (or whichever is next) CHANGELOG entry gets an "Added" line:
   > Management-port actuator endpoints are now JWT-authenticated (via
   > `opentmf-openid-rbac-security 2.1.0+`). `/actuator/env` values unredact
   > for callers with the `admin` role; others see `******`. See the
   > opentmf-openid-rbac-security README for the new
   > `opentmf.security.management.*` properties.
3. Sanity-check at least one other opentmf microservice that sets
   `management.server.port` (if any) — their actuator endpoints will start
   requiring JWT where they didn't before. Coordinate, or they get surprised
   on the upgrade.

---

## 11. Non-goals worth reaffirming

- Not rewriting the main-port filter chain.
- Not inventing a new JWT format or decoder. The management chain reuses
  whatever the main chain uses.
- Not implementing per-endpoint redaction. That's Spring Boot's job via
  `management.endpoint.*.show-values` / `show-components`. Our chain just
  ensures `SecurityContextHolder` is populated, which is the precondition for
  those checks to work.
- Not exposing actuator on the main port. Consumers who want that simply don't
  set `management.server.port`.
- Not adding RBAC for endpoints we don't know about (e.g. custom
  `@Endpoint`-annotated beans). Consumers define them in `secure-endpoints`
  under `opentmf.security.management.*` using standard path patterns.
