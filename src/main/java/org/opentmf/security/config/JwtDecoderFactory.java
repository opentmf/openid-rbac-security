package org.opentmf.security.config;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.SignedJWT;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.Predicate;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.opentmf.security.util.ReactiveResourceRetriever;
import org.opentmf.security.util.ServletResourceRetriever;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.util.ResourceUtils;
import reactor.core.publisher.Flux;

/**
 * Builds one stack's {@link JwtDecoder} for a {@link ResolvedIssuer}, keeping the classpath /
 * file JWKS support that the remote-URL decoders do not provide.
 *
 * <p>Validators follow the entry: an issuer-pinning validator and — when the entry declares
 * audiences — an {@code aud} validator are layered on top of Spring Security's defaults. An
 * entry that pins nothing (single-issuer mode) keeps the decoder's stock validators untouched,
 * so pre-2.3.0 behavior is preserved exactly.
 *
 * @author Gokhan Demir
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
final class JwtDecoderFactory {

  static JwtDecoder servletDecoder(ResolvedIssuer issuer) {
    NimbusJwtDecoder decoder = buildServletDecoder(issuer);
    additionalValidators(issuer).ifPresent(
        validators -> decoder.setJwtValidator(JwtValidators.createDefaultWithValidators(validators)));
    return decoder;
  }

  static ReactiveJwtDecoder reactiveDecoder(ResolvedIssuer issuer) {
    NimbusReactiveJwtDecoder decoder = buildReactiveDecoder(issuer);
    additionalValidators(issuer).ifPresent(
        validators -> decoder.setJwtValidator(JwtValidators.createDefaultWithValidators(validators)));
    return decoder;
  }

  private static NimbusJwtDecoder buildServletDecoder(ResolvedIssuer issuer) {
    URL url = jwkSetUrl(issuer);
    if (!ResourceUtils.isFileURL(url)) {
      return NimbusJwtDecoder.withJwkSetUri(url.toString()).build();
    }
    JWKSource<SecurityContext> source = JWKSourceBuilder
        .create(url, new ServletResourceRetriever())
        .build();
    JWSKeySelector<SecurityContext> selector =
        new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, source);
    return NimbusJwtDecoder
        .withJwkSetUri(url.toString())
        .jwtProcessorCustomizer(jwtProcessor -> jwtProcessor.setJWSKeySelector(selector))
        .build();
  }

  private static NimbusReactiveJwtDecoder buildReactiveDecoder(ResolvedIssuer issuer) {
    URL url = jwkSetUrl(issuer);
    if (!ResourceUtils.isFileURL(url)) {
      return new NimbusReactiveJwtDecoder(url.toString());
    }
    ReactiveResourceRetriever retriever = new ReactiveResourceRetriever(issuer.jwkSetUri());
    Function<SignedJWT, Flux<JWK>> jwkSource = signedJwt -> retriever.getKeys();
    return NimbusReactiveJwtDecoder.withJwkSource(jwkSource).build();
  }

  private static URL jwkSetUrl(ResolvedIssuer issuer) {
    try {
      return issuer.jwkSetUri().getURL();
    } catch (IOException e) {
      throw new IllegalArgumentException(
          "Exception during jwtDecoder configuration for issuer " + issuer.name(), e);
    }
  }

  /**
   * The validators to layer on top of the stock ones, or empty when this entry pins nothing
   * and the decoder must keep its default validation.
   */
  private static Optional<List<OAuth2TokenValidator<Jwt>>> additionalValidators(
      ResolvedIssuer issuer) {
    List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
    if (issuer.pinsIssuer()) {
      validators.add(new JwtIssuerValidator(issuer.issuer()));
    }
    if (!issuer.audiences().isEmpty()) {
      validators.add(audienceValidator(issuer.audiences()));
    }
    return validators.isEmpty() ? Optional.empty() : Optional.of(validators);
  }

  private static OAuth2TokenValidator<Jwt> audienceValidator(List<String> accepted) {
    Predicate<List<String>> carriesAnAcceptedAudience =
        audience -> audience != null && !Collections.disjoint(audience, accepted);
    return new JwtClaimValidator<>(JwtClaimNames.AUD, carriesAnAcceptedAudience);
  }
}
