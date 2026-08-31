package org.opentmf.security.config;

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
   * Rejects non-upper-case {@code method} values at startup instead of letting relaxed enum
   * binding silently activate a previously-dead rule; see {@link EndpointMethodCaseGuard}.
   */
  @Bean
  EndpointMethodCaseGuard endpointMethodCaseGuard(Environment environment) {
    return new EndpointMethodCaseGuard(environment);
  }
}
