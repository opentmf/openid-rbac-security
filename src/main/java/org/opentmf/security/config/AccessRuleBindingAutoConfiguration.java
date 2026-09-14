package org.opentmf.security.config;

import org.springframework.boot.LazyInitializationExcludeFilter;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;

/**
 * Registers the startup guards for the access-rule properties. Stack-neutral on purpose: the
 * properties bind the same way whichever web stack the consumer runs.
 *
 * @author Gokhan Demir
 */
@AutoConfiguration
public class AccessRuleBindingAutoConfiguration {

  /**
   * Rejects misspelled {@code method} values at startup instead of letting relaxed enum
   * binding silently activate a previously-dead rule; see {@link EndpointMethodCaseGuard}.
   */
  @Bean
  EndpointMethodCaseGuard endpointMethodCaseGuard(Environment environment) {
    return new EndpointMethodCaseGuard(environment);
  }

  /**
   * Refuses a configuration that still sets a retired property, instead of letting Boot ignore
   * it silently; see {@link RetiredPropertyGuard}.
   */
  @Bean
  RetiredPropertyGuard retiredPropertyGuard(Environment environment) {
    return new RetiredPropertyGuard(environment);
  }

  /**
   * The guards are referenced by nothing, so under {@code spring.main.lazy-initialization=true}
   * they would never be instantiated and the checks would silently not run. A security guard
   * must not be optional-by-tuning; this pins them eager.
   */
  @Bean
  static LazyInitializationExcludeFilter accessRuleGuardsAreNeverLazy() {
    return LazyInitializationExcludeFilter.forBeanTypes(
        EndpointMethodCaseGuard.class, RetiredPropertyGuard.class);
  }
}
