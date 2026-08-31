package org.opentmf.security.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.opentmf.security.config.AccessRuleBindingAutoConfiguration;
import org.opentmf.security.config.EndpointMethodCaseGuard;
import org.opentmf.security.config.ServletJwtAutoConfiguration;
import org.opentmf.security.config.ServletSecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.context.properties.bind.BindException;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.boot.webmvc.autoconfigure.WebMvcAutoConfiguration;
import org.springframework.http.HttpMethod;
import org.springframework.mock.env.MockEnvironment;

/**
 * The access-rule method is deliberately narrower than Spring's {@code HttpMethod}. A deployment
 * that names a verb outside the five must fail to start rather than bind to something that
 * quietly never applies — which is exactly what a separate {@code HEAD} rule used to do, since
 * the {@code GET} rule registered ahead of it always matched first.
 *
 * <p>Case is held to the same standard: before 3.0.0 a non-upper-case value never matched any
 * request (it bound through the case-preserving {@code HttpMethod.valueOf} and the matchers
 * compare exact strings), so the rule was dead. Relaxed enum binding would silently activate it
 * on upgrade; {@link EndpointMethodCaseGuard} fails startup instead — as a check over the raw
 * configuration, because a rejecting {@code @ConfigurationPropertiesBinding} converter does not
 * fail the bind: Boot falls through to the next conversion service, which accepts leniently.
 *
 * @author Gokhan Demir
 */
class EndpointMethodBindingTest {

  @ParameterizedTest
  @EnumSource(EndpointMethod.class)
  void everySupportedMethod_binds(EndpointMethod method) {
    Endpoint endpoint = bind(method.name());

    assertThat(endpoint.getMethod()).isEqualTo(method);
  }

  @ParameterizedTest
  @ValueSource(strings = {"HEAD", "OPTIONS", "TRACE", "CONNECT"})
  void aMethodOutsideTheFive_failsToBind(String method) {
    assertThatThrownBy(() -> bind(method))
        .isInstanceOf(BindException.class)
        .hasMessageContaining("opentmf.security.endpoint");
  }

  /**
   * Every spelling Boot's lenient conversion would map onto a constant — case differences,
   * separator characters, stray whitespace — is a dead 2.x rule that would silently come alive,
   * and must be rejected.
   */
  @ParameterizedTest
  @ValueSource(strings = {"get", "Get", "gEt", "G-E-T", "G_E_T", "GET ", " get"})
  void theGuard_rejectsASpellingLenientBindingWouldAccept(String method) {
    MockEnvironment environment = new MockEnvironment()
        .withProperty("opentmf.security.allowed-endpoints[0].method", method)
        .withProperty("opentmf.security.allowed-endpoints[0].path", "/internal");
    EndpointMethodCaseGuard guard = new EndpointMethodCaseGuard(environment);

    assertThatThrownBy(guard::afterPropertiesSet)
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("must be spelled exactly 'GET'")
        .hasMessageContaining("allowed-endpoints[0]");
  }

  /** A value lenient binding cannot map either is left to the real bind and its own failure. */
  @Test
  void theGuard_leavesAnUnmappableValueToTheRealBind() {
    MockEnvironment environment = new MockEnvironment()
        .withProperty("opentmf.security.allowed-endpoints[0].method", "FOO")
        .withProperty("opentmf.security.allowed-endpoints[0].path", "/internal");

    assertThatCode(() -> new EndpointMethodCaseGuard(environment).afterPropertiesSet())
        .doesNotThrowAnyException();
  }

  @Test
  void theGuard_alsoWatchesTheManagementSection() {
    MockEnvironment environment = new MockEnvironment()
        .withProperty("opentmf.security.management.secure-endpoints[0].method", "post")
        .withProperty("opentmf.security.management.secure-endpoints[0].path", "/loggers");
    EndpointMethodCaseGuard guard = new EndpointMethodCaseGuard(environment);

    assertThatThrownBy(guard::afterPropertiesSet)
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("management.secure-endpoints[0]");
  }

  @Test
  void theGuard_acceptsUpperCaseRulesAndSilence() {
    MockEnvironment environment = new MockEnvironment()
        .withProperty("opentmf.security.secure-endpoints[0].method", "DELETE")
        .withProperty("opentmf.security.secure-endpoints[0].path", "/car")
        .withProperty("opentmf.security.secure-endpoints[0].roles", "admin");

    assertThatCode(() -> new EndpointMethodCaseGuard(environment).afterPropertiesSet())
        .doesNotThrowAnyException();
    assertThatCode(() -> new EndpointMethodCaseGuard(new MockEnvironment()).afterPropertiesSet())
        .doesNotThrowAnyException();
  }

  /**
   * The guard only protects what it is wired into: this pins the auto-configuration actually
   * registering it, so a lowercase rule stops a real application.
   */
  @Test
  void theAutoConfiguration_rejectsALowercaseRuleAtStartup() {
    new WebApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(
            AccessRuleBindingAutoConfiguration.class,
            WebMvcAutoConfiguration.class,
            ServletJwtAutoConfiguration.class,
            ServletSecurityAutoConfiguration.class))
        .withPropertyValues(
            "opentmf.security.jwk-set-uri=classpath:jwk-set.json",
            "opentmf.security.allowed-endpoints[0].method=get",
            "opentmf.security.allowed-endpoints[0].path=/internal")
        .run(context -> {
          assertThat(context).hasFailed();
          assertThat(context.getStartupFailure())
              .rootCause()
              .hasMessageContaining("must be spelled exactly 'GET'");
        });
  }

  @ParameterizedTest
  @EnumSource(EndpointMethod.class)
  void toHttpMethod_mapsOntoSpringsOwnConstant(EndpointMethod method) {
    assertThat(method.toHttpMethod()).isEqualTo(HttpMethod.valueOf(method.name()));
  }

  private static Endpoint bind(String method) {
    MapConfigurationPropertySource source = new MapConfigurationPropertySource(
        Map.of("opentmf.security.endpoint.method", method,
            "opentmf.security.endpoint.path", "/car"));
    return new Binder(source)
        .bind("opentmf.security.endpoint", Bindable.of(Endpoint.class))
        .get();
  }
}
