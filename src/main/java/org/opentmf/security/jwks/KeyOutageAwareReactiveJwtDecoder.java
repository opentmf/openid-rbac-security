package org.opentmf.security.jwks;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import reactor.core.publisher.Mono;

/**
 * The reactive twin of {@link KeyOutageAwareJwtDecoder}. The reactive decoder wraps a key-source
 * failure in an {@code IllegalStateException("Could not obtain the keys")} and leaves it
 * unmapped, so the classification starts there and finds the Nimbus cause one level below.
 *
 * @author Gokhan Demir
 */
@RequiredArgsConstructor
public class KeyOutageAwareReactiveJwtDecoder implements ReactiveJwtDecoder {

  private final ReactiveJwtDecoder delegate;
  private final IssuerKeys keys;

  @Override
  public Mono<Jwt> decode(String token) {
    return delegate.decode(token).onErrorMap(RuntimeException.class,
        ex -> KeyOutageClassifier.classify(ex, keys));
  }
}
