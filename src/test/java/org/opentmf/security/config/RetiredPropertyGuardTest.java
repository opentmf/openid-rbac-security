package org.opentmf.security.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.boot.webmvc.autoconfigure.WebMvcAutoConfiguration;
import org.springframework.mock.env.MockEnvironment;

/**
 * A retired property must stop the application rather than be ignored, on both sections and
 * however it is spelled; and the auto-configuration must actually wire the guard in.
 *
 * @author Gokhan Demir
 */
class RetiredPropertyGuardTest {

  @ParameterizedTest
  @ValueSource(strings = {
      "opentmf.security.unmatched-method-response",
      "opentmf.security.unmatchedMethodResponse",
      "opentmf.security.management.unmatched-method-response"})
  void aRetiredProperty_stopsTheApplication_namingTheReplacement(String property) {
    MockEnvironment environment = new MockEnvironment().withProperty(property, "deny");

    assertThatThrownBy(new RetiredPropertyGuard(environment)::afterPropertiesSet)
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("unmatched-method-response")
        .hasMessageContaining("'deny'")
        .hasMessageContaining("retired in 3.1.0")
        .hasMessageContaining("Remove the property");
  }

  @Test
  void silence_passes() {
    assertThatCode(new RetiredPropertyGuard(new MockEnvironment())::afterPropertiesSet)
        .doesNotThrowAnyException();
  }

  @Test
  void theAutoConfiguration_rejectsARetiredPropertyAtStartup() {
    new WebApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(
            AccessRuleBindingAutoConfiguration.class,
            WebMvcAutoConfiguration.class,
            JwksAutoConfiguration.class,
            ServletJwtAutoConfiguration.class,
            ServletSecurityAutoConfiguration.class))
        .withPropertyValues(
            "opentmf.security.jwk-set-uri=classpath:jwk-set.json",
            "opentmf.security.unmatched-method-response=method-not-allowed")
        .run(context -> {
          assertThat(context).hasFailed();
          assertThat(context.getStartupFailure())
              .rootCause()
              .hasMessageContaining("retired in 3.1.0");
        });
  }
}
