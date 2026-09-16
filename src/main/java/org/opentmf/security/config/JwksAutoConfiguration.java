package org.opentmf.security.config;

import lombok.RequiredArgsConstructor;
import org.opentmf.security.jwks.JwkSetWarmer;
import org.opentmf.security.jwks.TrustedIssuerKeys;
import org.opentmf.security.model.OpenTmfSecurityProperties;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * The signing keys of every trusted issuer, once per application: the stack-neutral source
 * both {@link ServletJwtSupport} and {@link ReactiveJwtSupport} decode with, and the warm-up
 * that loads them off the request path.
 *
 * @author Gokhan Demir
 */
@AutoConfiguration
@EnableConfigurationProperties(OpenTmfSecurityProperties.class)
@RequiredArgsConstructor
public class JwksAutoConfiguration {

  private final OpenTmfSecurityProperties properties;

  @Bean
  @ConditionalOnMissingBean
  TrustedIssuerKeys trustedIssuerKeys() {
    return new TrustedIssuerKeys(properties);
  }

  /**
   * Loads every issuer's signing keys once the application is ready — off the request path —
   * and, under {@code on-startup-failure: fail}, stops the application when none could be
   * loaded; see {@link JwkSetWarmer}.
   */
  @Bean
  JwkSetWarmer jwkSetWarmer(TrustedIssuerKeys trustedIssuerKeys) {
    return new JwkSetWarmer(
        trustedIssuerKeys.issuers(), properties.getJwks().getOnStartupFailure());
  }
}
