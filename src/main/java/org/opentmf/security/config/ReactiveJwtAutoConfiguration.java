package org.opentmf.security.config;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.SignedJWT;
import org.opentmf.security.model.OpenTmfSecurityProperties;
import org.opentmf.security.util.ReactiveResourceRetriever;
import java.io.IOException;
import java.util.function.Function;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.util.ResourceUtils;
import reactor.core.publisher.Flux;

/**
 * Configure and expose the jwtDecoder bean for use by JwtService.
 *
 * @author Gokhan Demir
 */
@AutoConfiguration
@EnableConfigurationProperties(OpenTmfSecurityProperties.class)
@RequiredArgsConstructor
@ConditionalOnWebApplication(type = Type.REACTIVE)
@Slf4j
public class ReactiveJwtAutoConfiguration {

  private final OpenTmfSecurityProperties openTmfSecurityProperties;

  @Bean
  public ReactiveJwtDecoder reactiveJwtDecoder2() throws IOException {
    var local = ResourceUtils.isFileURL(openTmfSecurityProperties.getJwkSetUri().getURL());
    return local ? customReactiveJwtDecoder() : defaultReactiveJwtDecoder();
  }

  private ReactiveJwtDecoder defaultReactiveJwtDecoder() throws IOException {
    var jwkSetUri = openTmfSecurityProperties.getJwkSetUri();
    return new NimbusReactiveJwtDecoder(jwkSetUri.getURL().toString());
  }

  private ReactiveJwtDecoder customReactiveJwtDecoder() {
    ReactiveResourceRetriever reactiveJwkSource = new ReactiveResourceRetriever(
        openTmfSecurityProperties.getJwkSetUri());
    Function<SignedJWT, Flux<JWK>> jwkSource = reactiveJwkSource::getKeys;
    return NimbusReactiveJwtDecoder.withJwkSource(jwkSource).build();
  }
}
