package org.opentmf.security.config;

import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.SignedJWT;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.opentmf.security.jwks.IssuerKeys;
import org.opentmf.security.jwks.KeyOutageAwareJwtDecoder;
import org.opentmf.security.jwks.KeyOutageAwareReactiveJwtDecoder;
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
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

/**
 * Builds one stack's decoder for a {@link ResolvedIssuer} over the issuer's cache-first
 * {@link IssuerKeys}, decorated so that a key-availability failure is answered as such.
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

  static JwtDecoder servletDecoder(ResolvedIssuer issuer, IssuerKeys keys) {
    NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSource(keys.source()).build();
    additionalValidators(issuer).ifPresent(validators ->
        decoder.setJwtValidator(JwtValidators.createDefaultWithValidators(validators)));
    return new KeyOutageAwareJwtDecoder(decoder, keys);
  }

  static ReactiveJwtDecoder reactiveDecoder(ResolvedIssuer issuer, IssuerKeys keys) {
    // The blocking key lookup — a cached read after the first load, a fetch before it — runs
    // off the event loop; a checked KeySourceException travels as the error signal unchanged.
    NimbusReactiveJwtDecoder decoder = NimbusReactiveJwtDecoder
        .withJwkSource(jwt -> Mono.fromCallable(() -> select(jwt, keys))
            .subscribeOn(Schedulers.boundedElastic())
            .flatMapMany(Flux::fromIterable))
        .build();
    additionalValidators(issuer).ifPresent(validators ->
        decoder.setJwtValidator(JwtValidators.createDefaultWithValidators(validators)));
    return new KeyOutageAwareReactiveJwtDecoder(decoder, keys);
  }

  private static List<JWK> select(SignedJWT jwt, IssuerKeys keys)
      throws KeySourceException {
    return keys.source().get(new JWKSelector(JWKMatcher.forJWSHeader(jwt.getHeader())), null);
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
