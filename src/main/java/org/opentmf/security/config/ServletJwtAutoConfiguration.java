package org.opentmf.security.config;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import org.opentmf.security.model.OpenTmfSecurityProperties;
import org.opentmf.security.util.ServletResourceRetriever;
import java.io.IOException;
import java.net.URL;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.util.ResourceUtils;

/**
 * Configure and expose the jwtDecoder bean for use by the JwtService and
 * ServletJwtAutoConfiguration.
 *
 * @author Gokhan Demir
 */
@AutoConfiguration
@EnableConfigurationProperties(OpenTmfSecurityProperties.class)
@RequiredArgsConstructor
public class ServletJwtAutoConfiguration {

  private final OpenTmfSecurityProperties openTmfSecurityProperties;

  @Bean
  JwtDecoder jwtDecoder() throws IOException {
    var local = ResourceUtils.isFileURL(openTmfSecurityProperties.getJwkSetUri().getURL());
    return local ? customJwtDecoder() : defaultJwtDecoder();
  }

  private JwtDecoder defaultJwtDecoder() throws IOException {
    var jwkSetUri = openTmfSecurityProperties.getJwkSetUri();
    return NimbusJwtDecoder.withJwkSetUri(jwkSetUri.getURL().toString()).build();
  }

  private JwtDecoder customJwtDecoder() {
    try {
      URL url = openTmfSecurityProperties.getJwkSetUri().getURL();
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
