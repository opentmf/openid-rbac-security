package com.pia.security.jwt;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSAlgorithmFamilyJWSKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.pia.security.model.PiaSecurityProperties;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.text.ParseException;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.util.Assert;
import org.springframework.web.client.RestTemplate;

/**
 * Configure and expose the jwtDecoder bean for use by JwtService.
 *
 * @author Gokhan Demir
 */
@AutoConfiguration
@EnableConfigurationProperties(PiaSecurityProperties.class)
@RequiredArgsConstructor
public class JwtAutoConfiguration {

  private final PiaSecurityProperties piaSecurityProperties;

  @Bean
  public JwtDecoder jwtDecoder() throws IOException, ParseException, KeySourceException {
    var jwtProcessor = new DefaultJWTProcessor<>();
    jwtProcessor.setJWSKeySelector(JWSAlgorithmFamilyJWSKeySelector.fromJWKSource(jwkSource()));
    return new NimbusJwtDecoder(jwtProcessor);
  }

  private JWKSource<SecurityContext> jwkSource() throws IOException, ParseException {
    var jsonWebKeySet = retrieveJwkSet();
    Assert.notNull(jsonWebKeySet, "JwkSet must not be empty");
    return new ImmutableJWKSet<>(
        JWKSet.load(new ByteArrayInputStream(jsonWebKeySet.getBytes(UTF_8))));
  }

  private String retrieveJwkSet() {
    var restTemplate = new RestTemplate();
    var response = restTemplate.getForEntity(piaSecurityProperties.getJwkSetUri(), String.class);
    Assert.notNull(response.getBody(), "Could not load jwk-set from " + piaSecurityProperties.getJwkSetUri());
    return response.getBody();
  }
}
