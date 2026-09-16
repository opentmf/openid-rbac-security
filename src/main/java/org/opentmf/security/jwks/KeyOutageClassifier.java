package org.opentmf.security.jwks;

import com.nimbusds.jose.jwk.source.JWKSetUnavailableException;
import com.nimbusds.jose.jwk.source.RateLimitReachedException;
import org.springframework.security.oauth2.jwt.BadJwtException;

/**
 * Tells an outage apart from a bad token, from the cause chain of a decoding failure.
 *
 * <p>The decoders must not learn this themselves: {@code NimbusJwtDecoder} turns any unchecked
 * exception out of a key source into {@code BadJwtException} — a {@code 401} for a caller whose
 * token may be perfectly valid — so the key source throws nothing of its own and the checked
 * Nimbus exceptions travel as they are, wrapped by the decoder; this walks the chain, outermost
 * first, and the first recognised cause decides:
 *
 * <ul>
 *   <li>a {@link JWKSetUnavailableException} (a failed fetch, an unparsable set, the cache's
 *       refresh timeout, or the outage TTL exceeded) → the keys are unavailable: {@code 503};</li>
 *   <li>a {@link RateLimitReachedException} → a refresh was wanted but the interval has not
 *       passed: an unknown key id when the keys were ever loaded ({@code 401}), an outage when
 *       they never were ({@code 503});</li>
 *   <li>anything else → the failure stands as it was.</li>
 * </ul>
 *
 * @author Gokhan Demir
 */
final class KeyOutageClassifier {

  private static final int MAX_DEPTH = 16;

  private KeyOutageClassifier() {
    // Static classification.
  }

  /**
   * Returns the exception to raise instead of the given failure, or the failure itself when it
   * is not a key-availability problem.
   */
  static RuntimeException classify(RuntimeException failure, IssuerKeys keys) {
    Throwable cause = failure;
    for (int depth = 0; cause != null && depth < MAX_DEPTH; cause = cause.getCause(), depth++) {
      if (cause instanceof JWKSetUnavailableException) {
        return unavailable(keys, failure);
      }
      if (cause instanceof RateLimitReachedException) {
        return keys.everLoaded()
            ? new BadJwtException(
                "Unknown key id for issuer '" + keys.name() + "'; a refresh is not due yet", failure)
            : unavailable(keys, failure);
      }
    }
    return failure;
  }

  private static JwkSetUnavailableException unavailable(IssuerKeys keys, Throwable failure) {
    return new JwkSetUnavailableException(keys.name(), keys.retryAfter(), failure);
  }
}
