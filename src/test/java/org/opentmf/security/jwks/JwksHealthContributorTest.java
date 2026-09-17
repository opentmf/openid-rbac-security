package org.opentmf.security.jwks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.opentmf.security.model.JwksProperties;
import org.opentmf.security.util.JwksServer;
import org.opentmf.security.util.TestIssuer;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthContributors;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.boot.health.contributor.Status;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.core.io.UrlResource;

/**
 * The {@code jwks} health across the three states, read from a real {@link IssuerKeys} against
 * a scriptable JWKS server — and the boot line naming the host.
 *
 * @author Gokhan Demir
 */
@ExtendWith(OutputCaptureExtension.class)
class JwksHealthContributorTest {

  static final TestIssuer ISSUER = TestIssuer.create("health", "https://health.test/realm");

  @Test
  void neverLoaded_isDown_namingTheIssuerAndTheFailure(CapturedOutput output) throws IOException {
    try (JwksServer server = JwksServer.start(ISSUER.jwkSetJson())) {
      server.fail(503);
      IssuerKeys keys = keys(server, new JwksProperties());
      keys.warmUp();

      Health health = JwksHealthContributor.healthOf(keys, Instant.now());

      assertThat(health.getStatus()).isEqualTo(Status.DOWN);
      assertThat(health.getDetails())
          .containsEntry("issuer", "idp")
          .containsEntry("state", "UNAVAILABLE")
          .containsEntry("keys", 0)
          .containsEntry("origin", "127.0.0.1")
          .hasEntrySatisfying("lastFailure", failure -> assertThat((String) failure)
              .contains("503").doesNotContain(JwksServer.PATH));
      assertThat(output).contains(
          "Signing keys of issuer 'idp' could not be loaded from 127.0.0.1 (direct)");
    }
  }

  @Test
  void loadedAndFresh_isUp(CapturedOutput output) throws IOException {
    try (JwksServer server = JwksServer.start(ISSUER.jwkSetJson())) {
      IssuerKeys keys = keys(server, new JwksProperties());
      keys.warmUp();

      Health health = JwksHealthContributor.healthOf(keys, Instant.now());

      assertThat(health.getStatus()).isEqualTo(Status.UP);
      assertThat(health.getDetails())
          .containsEntry("state", "FRESH")
          .containsEntry("keys", 1)
          .containsKey("loadedAt")
          .containsKey("age")
          .doesNotContainKey("stale")
          .doesNotContainKey("lastFailure");
      assertThat(output).contains("Signing keys of issuer 'idp' loaded (1 keys) from 127.0.0.1 (direct)");
    }
  }

  @Test
  void loadedButRefreshFailing_isUpWithStaleDetails_notDown() throws IOException {
    try (JwksServer server = JwksServer.start(ISSUER.jwkSetJson())) {
      JwksProperties properties = new JwksProperties();
      properties.setCacheTtl(Duration.ofMillis(300));
      properties.setRefreshInterval(Duration.ofMillis(100));
      IssuerKeys keys = keys(server, properties);
      keys.warmUp();
      server.fail(500);

      await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> {
        Health health = JwksHealthContributor.healthOf(keys, Instant.now());
        assertThat(health.getStatus()).isEqualTo(Status.UP);
        assertThat(health.getDetails())
            .containsEntry("state", "STALE")
            .containsEntry("stale", true)
            .containsKey("lastFailure")
            .hasEntrySatisfying("failures", count -> assertThat((Long) count).isPositive());
      });
    }
  }

  @Test
  void loadedButOlderThanTheOutageTtl_isDown() throws IOException {
    try (JwksServer server = JwksServer.start(ISSUER.jwkSetJson())) {
      JwksProperties properties = new JwksProperties();
      IssuerKeys keys = keys(server, properties);
      keys.warmUp();
      Instant longAfter = Instant.now().plus(properties.getOutageTtl()).plusSeconds(1);

      Health health = JwksHealthContributor.healthOf(keys, longAfter);

      assertThat(health.getStatus()).isEqualTo(Status.DOWN);
      assertThat(health.getDetails()).containsEntry("state", "UNAVAILABLE").containsEntry("keys", 1);
    }
  }

  @Test
  void theContributor_hasOneComponentPerIssuer_byName() throws IOException {
    try (JwksServer server = JwksServer.start(ISSUER.jwkSetJson())) {
      IssuerKeys keys = keys(server, new JwksProperties());
      JwksHealthContributor contributor =
          new JwksHealthContributor(List.of(keys), Clock.systemUTC());

      assertThat(contributor.stream().map(HealthContributors.Entry::name)).containsExactly("idp");
      assertThat(((HealthIndicator) contributor.getContributor("idp")).health().getStatus())
          .isEqualTo(Status.DOWN);
    }
  }

  private static IssuerKeys keys(JwksServer server, JwksProperties properties) throws IOException {
    return new IssuerKeys("idp", new UrlResource(server.url()), null, properties, name -> null);
  }
}
