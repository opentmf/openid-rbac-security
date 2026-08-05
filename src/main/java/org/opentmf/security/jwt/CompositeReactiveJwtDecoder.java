package org.opentmf.security.jwt;

import com.nimbusds.jwt.JWTParser;
import java.text.ParseException;
import java.util.Map;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import reactor.core.publisher.Mono;

/**
 * Reactive twin of {@link CompositeJwtDecoder}: routes a token to the
 * {@link ReactiveJwtDecoder} of the issuer named in its {@code iss} claim, so callers holding
 * the {@code ReactiveJwtDecoder} bean keep working across every configured issuer.
 *
 * @author Gokhan Demir
 */
public class CompositeReactiveJwtDecoder implements ReactiveJwtDecoder {

  private final Map<String, ReactiveJwtDecoder> decodersByIssuer;

  public CompositeReactiveJwtDecoder(Map<String, ReactiveJwtDecoder> decodersByIssuer) {
    this.decodersByIssuer = Map.copyOf(decodersByIssuer);
  }

  @Override
  public Mono<Jwt> decode(String token) {
    return Mono.fromCallable(() -> delegateFor(token))
        .flatMap(delegate -> delegate.decode(token));
  }

  private ReactiveJwtDecoder delegateFor(String token) {
    String issuer;
    try {
      issuer = JWTParser.parse(token).getJWTClaimsSet().getIssuer();
    } catch (ParseException e) {
      throw new BadJwtException("Failed to parse the token", e);
    }
    if (issuer == null) {
      throw new BadJwtException("The token carries no iss claim, so no trusted issuer applies");
    }
    ReactiveJwtDecoder delegate = decodersByIssuer.get(issuer);
    if (delegate == null) {
      throw new BadJwtException("No configured issuer matches the token's iss claim");
    }
    return delegate;
  }
}
