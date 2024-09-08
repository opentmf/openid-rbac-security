package com.pia.security.config;

import com.pia.security.model.PiaSecurityProperties;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

/**
 * Configure and expose the jwtDecoder bean for use by the JwtService and
 * ServletJwtAutoConfiguration.
 *
 * @author Gokhan Demir
 */
@AutoConfiguration
@EnableConfigurationProperties(PiaSecurityProperties.class)
@RequiredArgsConstructor
public class ServletJwtAutoConfiguration {

  private final PiaSecurityProperties piaSecurityProperties;

  @Bean
  public JwtDecoder jwtDecoder() throws IOException {
    var jwkSetUri = piaSecurityProperties.getJwkSetUri();
    return NimbusJwtDecoder.withJwkSetUri(jwkSetUri.getURL().toString()).build();
  }
}
