package org.opentmf.security.jwks;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.springframework.boot.health.contributor.CompositeHealthContributor;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthContributor;
import org.springframework.boot.health.contributor.HealthContributors;
import org.springframework.boot.health.contributor.HealthIndicator;

/**
 * The {@code jwks} health contributor: one component per trusted issuer, read from that issuer's
 * {@link IssuerKeys} and nothing else, so health cannot disagree with what the wire answers.
 *
 * <ul>
 *   <li>{@code UP} — a set is loaded and fresh;</li>
 *   <li>{@code UP} with {@code stale: true}, the age and the last failure — a set is loaded but
 *       refreshes are failing; it still serves, so readiness must not flip (a custom
 *       {@code DEGRADED} status would sort last in Boot's aggregator and map to {@code 200},
 *       reading as healthy while confusing every dashboard that groups by status);</li>
 *   <li>{@code DOWN} with the issuer, the last failure and since when — no set was ever loaded,
 *       or the loaded one is older than the outage TTL: exactly when every bearer request from
 *       that issuer answers {@code 503}.</li>
 * </ul>
 *
 * @author Gokhan Demir
 */
public class JwksHealthContributor implements CompositeHealthContributor {

  private final Map<String, HealthContributor> issuers = new LinkedHashMap<>();

  public JwksHealthContributor(List<IssuerKeys> keys, Clock clock) {
    for (IssuerKeys issuer : keys) {
      issuers.put(issuer.name(), (HealthIndicator) () -> healthOf(issuer, clock.instant()));
    }
  }

  static Health healthOf(IssuerKeys issuer, Instant now) {
    IssuerKeys.Snapshot snapshot = issuer.snapshot();
    IssuerKeys.State state = issuer.state(now);
    if (state == IssuerKeys.State.UNAVAILABLE) {
      // Nothing else retries a cold outage before the next bearer request; the probe does,
      // off its own thread, so a pod heals while it is NotReady and no traffic reaches it.
      issuer.retryInBackground();
    }
    Health.Builder health = state == IssuerKeys.State.UNAVAILABLE ? Health.down() : Health.up();
    health.withDetail("issuer", issuer.name())
        .withDetail("origin", issuer.origin())
        .withDetail("state", state.name())
        .withDetail("keys", snapshot.keys());
    if (snapshot.loadedAt() != null) {
      health.withDetail("loadedAt", snapshot.loadedAt())
          .withDetail("age", Duration.between(snapshot.loadedAt(), now).toString());
    }
    if (state == IssuerKeys.State.STALE) {
      health.withDetail("stale", true);
    }
    if (snapshot.lastFailure() != null) {
      health.withDetail("lastFailure", snapshot.lastFailure())
          .withDetail("failedAt", snapshot.failedAt())
          .withDetail("failures", snapshot.failures());
    }
    return health.build();
  }

  @Override
  public HealthContributor getContributor(String name) {
    return issuers.get(name);
  }

  @Override
  public Stream<HealthContributors.Entry> stream() {
    return issuers.entrySet().stream()
        .map(entry -> new HealthContributors.Entry(entry.getKey(), entry.getValue()));
  }
}
