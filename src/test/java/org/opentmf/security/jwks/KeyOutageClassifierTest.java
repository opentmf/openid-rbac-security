package org.opentmf.security.jwks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.nimbusds.jose.jwk.source.JWKSetParseException;
import com.nimbusds.jose.jwk.source.JWKSetRetrievalException;
import com.nimbusds.jose.jwk.source.JWKSetUnavailableException;
import com.nimbusds.jose.jwk.source.RateLimitReachedException;
import java.time.Duration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtException;

/**
 * The classification table, from the cause chain a decoder hands over.
 *
 * @author Gokhan Demir
 */
class KeyOutageClassifierTest {

  private final IssuerKeys keys = mock(IssuerKeys.class);

  @BeforeEach
  void setUp() {
    when(keys.name()).thenReturn("entra");
    when(keys.retryAfter()).thenReturn(Duration.ofSeconds(30));
  }

  @Test
  void aFailedFetch_isTheTyped503_namingTheIssuerNotTheUrl() {
    JwtException failure = new JwtException("decode", new IllegalStateException("wrapped",
        new JWKSetRetrievalException("Couldn't retrieve JWK set from https://secret/certs", null)));

    RuntimeException classified = KeyOutageClassifier.classify(failure, keys);

    assertThat(classified).isInstanceOf(JwkSetUnavailableException.class);
    JwkSetUnavailableException unavailable = (JwkSetUnavailableException) classified;
    assertThat(unavailable.getStatusCode().value()).isEqualTo(503);
    assertThat(unavailable.getHeaders().getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("30");
    assertThat(unavailable.getBody().getDetail()).contains("'entra'").doesNotContain("secret");
    assertThat(unavailable.getBody().getProperties()).containsEntry("issuer", "entra");
    assertThat(unavailable.getBody().getType()).isEqualTo(JwkSetUnavailableException.TYPE);
    assertThat(unavailable.getCause()).isSameAs(failure);
  }

  @Test
  void anUnparsableSet_andTheCacheTimeout_areOutagesToo() {
    assertThat(KeyOutageClassifier.classify(
        new JwtException("x", new JWKSetParseException("bad json", null)), keys))
        .isInstanceOf(JwkSetUnavailableException.class);
    assertThat(KeyOutageClassifier.classify(
        new JwtException("x", new JWKSetUnavailableException("Timeout while waiting")), keys))
        .isInstanceOf(JwkSetUnavailableException.class);
  }

  @Test
  void aRateLimitedMiss_whenTheKeysWereLoaded_isAnUnknownKeyId_thatIs401() {
    when(keys.everLoaded()).thenReturn(true);

    RuntimeException classified =
        KeyOutageClassifier.classify(new JwtException("x", new RateLimitReachedException()), keys);

    assertThat(classified).isInstanceOf(BadJwtException.class);
    assertThat(classified.getMessage()).contains("Unknown key id").contains("'entra'");
  }

  @Test
  void aRateLimitedMiss_whenTheKeysWereNeverLoaded_isAnOutage() {
    when(keys.everLoaded()).thenReturn(false);

    assertThat(KeyOutageClassifier.classify(
        new JwtException("x", new RateLimitReachedException()), keys))
        .isInstanceOf(JwkSetUnavailableException.class);
  }

  @Test
  void anyOtherFailure_standsAsItWas() {
    JwtException bad = new BadJwtException("expired");
    JwtException other = new JwtException("no verifier", new IllegalStateException("cfg"));

    assertThat(KeyOutageClassifier.classify(bad, keys)).isSameAs(bad);
    assertThat(KeyOutageClassifier.classify(other, keys)).isSameAs(other);
  }
}
