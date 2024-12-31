package com.pia.security.config;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.pia.security.model.PiaSecurityProperties;
import com.pia.security.util.ServletResourceRetriever;
import java.io.IOException;
import java.net.URL;
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
  public JwtDecoder jwtDecoder() {
    try {
      URL url = piaSecurityProperties.getJwkSetUri().getURL();
      JWKSource<SecurityContext> source = JWKSourceBuilder
          .create(url, new ServletResourceRetriever())
          .build();
      JWSKeySelector<SecurityContext> selector =
          new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, source);

      return NimbusJwtDecoder
          .withJwkSetUri(url.toString())
          .jwtProcessorCustomizer(jwtProcessor -> jwtProcessor.setJWSKeySelector(selector))
          .build();
    } catch (IOException e) {
      throw new IllegalArgumentException("Exception during jwtDecoder configuration", e);
    }
  }
}
