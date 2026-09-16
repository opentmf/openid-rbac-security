package org.opentmf.security.jwks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.opentmf.security.TestApplication;
import org.opentmf.security.model.JwksStartupFailure;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;

/**
 * The startup policy: {@code WARN} boots and warms up in the background, {@code FAIL} stops the
 * application by name when no issuer's keys could be loaded — and boots when at least one could.
 *
 * @author Gokhan Demir
 */
class JwkSetWarmerTest {

  @Test
  void fail_stopsWhenNoIssuerLoaded_namingThem() {
    JwkSetWarmer warmer = new JwkSetWarmer(
        List.of(issuer("entra", false), issuer("keycloak", false)), JwksStartupFailure.FAIL);

    assertThatThrownBy(warmer::onApplicationReady)
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("entra, keycloak")
        .hasMessageContaining("on-startup-failure is FAIL");
  }

  @Test
  void fail_bootsWhenAtLeastOneIssuerLoaded() {
    JwkSetWarmer warmer = new JwkSetWarmer(
        List.of(issuer("entra", false), issuer("keycloak", true)), JwksStartupFailure.FAIL);

    assertThatCode(warmer::onApplicationReady).doesNotThrowAnyException();
  }

  @Test
  void warn_neverStops() {
    JwkSetWarmer warmer =
        new JwkSetWarmer(List.of(issuer("entra", false)), JwksStartupFailure.WARN);

    assertThatCode(warmer::onApplicationReady).doesNotThrowAnyException();
    assertThat(warmer.warmUpAll()).isZero();
  }

  /** The policy is wired into a real application: an unreachable issuer stops it under FAIL. */
  @Test
  void aRealApplication_underFail_doesNotStartWithoutKeys() {
    SpringApplicationBuilder application = new SpringApplicationBuilder(TestApplication.class)
        .web(WebApplicationType.NONE)
        .properties(
            "opentmf.security.jwk-set-uri=http://127.0.0.1:1/certs",
            "opentmf.security.jwks.connect-timeout=1s",
            "opentmf.security.jwks.read-timeout=1s",
            "opentmf.security.jwks.on-startup-failure=fail");

    assertThatThrownBy(application::run)
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("single-issuer")
        .hasMessageContaining("on-startup-failure is FAIL");
  }

  @Test
  void aRealApplication_underWarn_startsWithoutKeys() {
    SpringApplicationBuilder application = new SpringApplicationBuilder(TestApplication.class)
        .web(WebApplicationType.NONE)
        .properties(
            "opentmf.security.jwk-set-uri=http://127.0.0.1:1/certs",
            "opentmf.security.jwks.connect-timeout=1s",
            "opentmf.security.jwks.read-timeout=1s");

    try (ConfigurableApplicationContext context = application.run()) {
      assertThat(context.isRunning()).isTrue();
    }
  }

  private static IssuerKeys issuer(String name, boolean loads) {
    IssuerKeys keys = mock(IssuerKeys.class);
    when(keys.name()).thenReturn(name);
    when(keys.warmUp()).thenReturn(loads);
    return keys;
  }
}
