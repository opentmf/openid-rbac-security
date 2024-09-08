package com.pia.security.config;

import com.pia.security.model.PiaSecurityProperties;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;

/**
 * Configure and expose the jwtDecoder bean for use by JwtService.
 *
 * @author Gokhan Demir
 */
@AutoConfiguration
@EnableConfigurationProperties(PiaSecurityProperties.class)
@RequiredArgsConstructor
@ConditionalOnWebApplication(type = Type.REACTIVE)
public class ReactiveJwtAutoConfiguration {

  private final PiaSecurityProperties piaSecurityProperties;

  @Bean
  public ReactiveJwtDecoder reactiveJwtDecoder() throws IOException {
    var jwkSetUri = piaSecurityProperties.getJwkSetUri();
    return new NimbusReactiveJwtDecoder(jwkSetUri.getURL().toString());
  }
}
