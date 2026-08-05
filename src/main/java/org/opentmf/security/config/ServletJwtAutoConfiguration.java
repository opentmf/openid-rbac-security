package org.opentmf.security.config;

import lombok.RequiredArgsConstructor;
import org.opentmf.security.model.OpenTmfSecurityProperties;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.jwt.JwtDecoder;

/**
 * Configure and expose the jwtDecoder bean for use by the JwtService and
 * ServletSecurityAutoConfiguration.
 *
 * @author Gokhan Demir
 */
@AutoConfiguration
@EnableConfigurationProperties(OpenTmfSecurityProperties.class)
@RequiredArgsConstructor
public class ServletJwtAutoConfiguration {

  private final OpenTmfSecurityProperties openTmfSecurityProperties;

  @Bean
  @ConditionalOnMissingBean
  ServletJwtSupport servletJwtSupport() {
    return new ServletJwtSupport(openTmfSecurityProperties);
  }

  /**
   * Kept as a bean in its own right: {@code JwtService} and consumer code inject it directly.
   * With multiple issuers configured it routes by the token's {@code iss}, so those callers
   * keep working across every trusted issuer.
   */
  @Bean
  JwtDecoder jwtDecoder(ServletJwtSupport servletJwtSupport) {
    return servletJwtSupport.getDecoder();
  }
}
