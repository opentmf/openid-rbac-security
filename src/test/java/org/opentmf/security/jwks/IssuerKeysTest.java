package org.opentmf.security.jwks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSetUnavailableException;
import com.nimbusds.jose.jwk.source.RateLimitReachedException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.opentmf.security.model.JwksProperties;
import org.opentmf.security.util.ForwardProxy;
import org.opentmf.security.util.JwksServer;
import org.opentmf.security.util.TestIssuer;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.UrlResource;

/**
 * The cache-first key source against a scriptable JWKS server: the first load, key rotation,
 * the rate limit, stale serving during an outage, the cold outage — and every local shape a
 * JWK set can come in, network-free.
 *
 * @author Gokhan Demir
 */
class IssuerKeysTest {

  static final TestIssuer FIRST = TestIssuer.create("keys-first", "https://keys.test/first");
  static final TestIssuer ROTATED = TestIssuer.create("keys-rotated", "https://keys.test/first");
  static JwksServer server;

  @BeforeAll
  static void startServer() {
    server = JwksServer.start(FIRST.jwkSetJson());
  }

  @AfterAll
  static void stopServer() {
    server.close();
  }

  // ------------------------------------------------------------------ remote

  @Test
  void theFirstLoad_flipsEverLoaded_andWarmUpSaysSo() throws Exception {
    IssuerKeys keys = remote(properties());

    assertThat(keys.everLoaded()).isFalse();
    assertThat(keys.warmUp()).isTrue();
    assertThat(keys.everLoaded()).isTrue();
    assertThat(keys.remote()).isTrue();
    assertThat(select(keys, FIRST.keyId())).extracting(JWK::getKeyID).containsExactly(FIRST.keyId());
  }

  @Test
  void aColdSourceWhoseServerFails_throwsUnavailable_andWarmUpReportsIt() {
    try (JwksServer failing = JwksServer.start(FIRST.jwkSetJson())) {
      failing.fail(503);
      IssuerKeys keys = new IssuerKeys("cold", new UrlResource(failing.url()), null,
          properties(), name -> null);

      assertThat(keys.warmUp()).isFalse();
      assertThat(keys.everLoaded()).isFalse();
      assertThatThrownBy(() -> select(keys, FIRST.keyId()))
          .isInstanceOf(JWKSetUnavailableException.class);
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }

  @Test
  void anUnknownKeyId_triggersOneRefresh_andRotationIsPickedUp() throws Exception {
    try (JwksServer rotating = JwksServer.start(FIRST.jwkSetJson())) {
      IssuerKeys keys = new IssuerKeys("rotating", new UrlResource(rotating.url()), null,
          properties(), name -> null);
      keys.warmUp();
      int fetchesAfterWarmUp = rotating.fetches();

      rotating.serve(ROTATED.jwkSetJson());
      List<JWK> found = select(keys, ROTATED.keyId());

      assertThat(found).extracting(JWK::getKeyID).containsExactly(ROTATED.keyId());
      assertThat(rotating.fetches()).isEqualTo(fetchesAfterWarmUp + 1);
    }
  }

  @Test
  void aFloodOfUnknownKeyIds_isRateLimited_whileKnownKeysKeepServing() throws Exception {
    try (JwksServer flooded = JwksServer.start(FIRST.jwkSetJson())) {
      JwksProperties properties = properties();
      properties.setRefreshInterval(Duration.ofMinutes(1));
      IssuerKeys keys = new IssuerKeys("flooded", new UrlResource(flooded.url()), null,
          properties, name -> null);
      keys.warmUp();
      int fetchesAfterWarmUp = flooded.fetches();

      // The window the warm-up opened admits one more refresh, then the limiter closes.
      assertThat(select(keys, "unknown-1")).isEmpty();
      assertThatThrownBy(() -> select(keys, "unknown-2"))
          .isInstanceOf(RateLimitReachedException.class);
      assertThat(flooded.fetches()).isEqualTo(fetchesAfterWarmUp + 1);
      assertThat(select(keys, FIRST.keyId())).hasSize(1);
      assertThat(keys.everLoaded()).isTrue();
    }
  }

  @Test
  void afterTheCacheExpires_anOutageIsServedFromTheStaleSet() throws Exception {
    try (JwksServer flaky = JwksServer.start(FIRST.jwkSetJson())) {
      JwksProperties properties = properties();
      properties.setCacheTtl(Duration.ofMillis(300));
      properties.setRefreshInterval(Duration.ofMillis(100));
      IssuerKeys keys = new IssuerKeys("flaky", new UrlResource(flaky.url()), null,
          properties, name -> null);
      keys.warmUp();
      int fetchesAfterWarmUp = flaky.fetches();
      flaky.fail(500);

      // Once the cache has expired, a refresh has been attempted and failed — and the stale set
      // is what the source still answers with.
      await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> {
        assertThat(flaky.fetches()).isGreaterThan(fetchesAfterWarmUp);
        assertThat(select(keys, FIRST.keyId()))
            .extracting(JWK::getKeyID).containsExactly(FIRST.keyId());
      });
    }
  }

  @Test
  void aConfiguredProxy_carriesTheFetch() throws Exception {
    try (ForwardProxy proxy = ForwardProxy.start()) {
      IssuerKeys keys = new IssuerKeys("proxied", new UrlResource(server.url()),
          proxy.hostPort(), properties(), name -> null);

      assertThat(keys.warmUp()).isTrue();
      assertThat(proxy.forwarded()).containsExactly("GET " + server.url());
    }
  }

  @Test
  void theEnvironmentProxy_carriesTheFetch_unlessNoProxyExcludesTheHost() throws Exception {
    try (ForwardProxy proxy = ForwardProxy.start()) {
      IssuerKeys viaEnvironment = new IssuerKeys("env", new UrlResource(server.url()), null,
          properties(), variable -> "HTTP_PROXY".equals(variable) ? proxy.hostPort() : null);
      IssuerKeys excluded = new IssuerKeys("excluded", new UrlResource(server.url()), null,
          properties(), variable -> switch (variable) {
            case "HTTP_PROXY" -> proxy.hostPort();
            case "NO_PROXY" -> "127.0.0.1";
            default -> null;
          });

      assertThat(viaEnvironment.warmUp()).isTrue();
      assertThat(excluded.warmUp()).isTrue();
      assertThat(proxy.forwarded()).containsExactly("GET " + server.url());
    }
  }

  // ------------------------------------------------------------------ local

  @Test
  void aClasspathJwkSet_loadsWithoutTheNetwork() throws Exception {
    IssuerKeys keys = new IssuerKeys("classpath", new ClassPathResource("jwk-set.json"), null,
        properties(), name -> null);

    assertThat(keys.remote()).isFalse();
    assertThat(keys.warmUp()).isTrue();
    assertThat(select(keys, null)).isNotEmpty();
  }

  @Test
  void aFileJwkSet_loadsWithoutTheNetwork(@TempDir Path dir) throws Exception {
    Path file = dir.resolve("jwks.json");
    Files.writeString(file, FIRST.jwkSetJson());
    IssuerKeys keys = new IssuerKeys("file", new FileSystemResource(file), null,
        properties(), name -> null);

    assertThat(keys.warmUp()).isTrue();
    assertThat(select(keys, FIRST.keyId())).hasSize(1);
  }

  /**
   * A JWK set packed inside a jar — the shape a {@code classpath:} resource takes in a Boot fat
   * jar. On 3.1.0 the {@code jar:} URL was handed to the HTTP decoder, which casts the
   * {@code JarURLConnection} to {@code HttpURLConnection} and fails every bearer request.
   */
  @Test
  void aJwkSetInsideAJar_loadsWithoutTheNetwork(@TempDir Path dir) throws Exception {
    Path jar = dir.resolve("keys.jar");
    try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(jar))) {
      out.putNextEntry(new JarEntry("jwks.json"));
      out.write(FIRST.jwkSetJson().getBytes());
      out.closeEntry();
    }
    IssuerKeys keys = new IssuerKeys("jar",
        new UrlResource("jar:" + jar.toUri() + "!/jwks.json"), null, properties(), name -> null);

    assertThat(keys.remote()).isFalse();
    assertThat(keys.warmUp()).isTrue();
    assertThat(select(keys, FIRST.keyId())).hasSize(1);
  }

  @Test
  void aMissingFile_isReportedByName_andThrowsUnavailable(@TempDir Path dir) {
    IssuerKeys keys = new IssuerKeys("missing",
        new FileSystemResource(dir.resolve("absent.json")), null, properties(), name -> null);

    assertThat(keys.warmUp()).isFalse();
    assertThatThrownBy(() -> select(keys, "any")).isInstanceOf(JWKSetUnavailableException.class);
  }

  private static IssuerKeys remote(JwksProperties properties) throws IOException {
    return new IssuerKeys("remote", new UrlResource(server.url()), null, properties, name -> null);
  }

  private static JwksProperties properties() {
    return new JwksProperties();
  }

  private static List<JWK> select(IssuerKeys keys, String keyId) throws KeySourceException {
    JWKMatcher.Builder matcher = new JWKMatcher.Builder();
    if (keyId != null) {
      matcher.keyID(keyId);
    }
    return keys.source().get(new JWKSelector(matcher.build()), null);
  }
}
