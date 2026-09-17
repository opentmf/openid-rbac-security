package org.opentmf.security.jwks;

import io.micrometer.core.instrument.FunctionCounter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.binder.MeterBinder;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import lombok.RequiredArgsConstructor;

/**
 * The signing keys on the dashboards, per issuer (tag {@code issuer} = the configured name):
 * {@code opentmf.security.jwks.keys} (the loaded set's size, 0 before the first load),
 * {@code opentmf.security.jwks.keys.age} (seconds since the last successful load, {@code NaN}
 * before it) and {@code opentmf.security.jwks.fetch.failures} (failed loads). Always on when
 * Micrometer is present: a metric that exists only when someone remembers to enable it is not a
 * dashboard.
 *
 * @author Gokhan Demir
 */
@RequiredArgsConstructor
public class JwksMetrics implements MeterBinder {

  static final String KEYS = "opentmf.security.jwks.keys";
  static final String KEYS_AGE = "opentmf.security.jwks.keys.age";
  static final String FETCH_FAILURES = "opentmf.security.jwks.fetch.failures";
  static final String ISSUER = "issuer";

  private final List<IssuerKeys> issuers;
  private final Clock clock;

  @Override
  public void bindTo(MeterRegistry registry) {
    for (IssuerKeys issuer : issuers) {
      Gauge.builder(KEYS, issuer, keys -> keys.snapshot().keys())
          .description("Number of signing keys loaded for the issuer")
          .tag(ISSUER, issuer.name())
          .register(registry);
      Gauge.builder(KEYS_AGE, issuer, this::ageSeconds)
          .description("Seconds since the issuer's signing keys were last loaded")
          .baseUnit("seconds")
          .tag(ISSUER, issuer.name())
          .register(registry);
      FunctionCounter.builder(FETCH_FAILURES, issuer, keys -> keys.snapshot().failures())
          .description("Failed loads of the issuer's signing keys")
          .tag(ISSUER, issuer.name())
          .register(registry);
    }
  }

  private double ageSeconds(IssuerKeys issuer) {
    IssuerKeys.Snapshot snapshot = issuer.snapshot();
    if (snapshot.loadedAt() == null) {
      return Double.NaN;
    }
    return Duration.between(snapshot.loadedAt(), clock.instant()).toMillis() / 1000.0;
  }
}
