package org.opentmf.security.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.opentmf.security.jwks.TrustedIssuerKeys;
import org.opentmf.security.model.OpenTmfSecurityProperties;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;

/**
 * Configure and expose the jwtDecoder bean for use by JwtService.
 *
 * @author Gokhan Demir
 */
@AutoConfiguration(after = JwksAutoConfiguration.class)
@EnableConfigurationProperties(OpenTmfSecurityProperties.class)
@RequiredArgsConstructor
@ConditionalOnWebApplication(type = Type.REACTIVE)
@Slf4j
public class ReactiveJwtAutoConfiguration {

  private final OpenTmfSecurityProperties openTmfSecurityProperties;

  @Bean
  @ConditionalOnMissingBean
  ReactiveJwtSupport reactiveJwtSupport(TrustedIssuerKeys trustedIssuerKeys) {
    return new ReactiveJwtSupport(openTmfSecurityProperties, trustedIssuerKeys);
  }

  /**
   * With multiple issuers configured this routes by the token's {@code iss}, so consumers
   * injecting the decoder keep working across every trusted issuer.
   */
  @Bean
  ReactiveJwtDecoder reactiveJwtDecoder2(ReactiveJwtSupport reactiveJwtSupport) {
    return reactiveJwtSupport.getDecoder();
  }
}
