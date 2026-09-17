package org.opentmf.security.config;

import io.micrometer.core.instrument.MeterRegistry;
import java.time.Clock;
import org.opentmf.security.jwks.JwksHealthContributor;
import org.opentmf.security.jwks.JwksMetrics;
import org.opentmf.security.jwks.JwksReadinessGroupPostProcessor;
import org.opentmf.security.jwks.TrustedIssuerKeys;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.health.actuate.endpoint.HealthEndpointGroupsPostProcessor;
import org.springframework.boot.health.autoconfigure.contributor.ConditionalOnEnabledHealthIndicator;
import org.springframework.boot.health.contributor.HealthContributor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

/**
 * What the signing keys tell the platform: the {@code jwks} health contributor and its readiness
 * membership behind {@code opentmf.security.jwks.readiness} (off by default — no adopter's health
 * or readiness changes without a decision), and the per-issuer metrics, always on when Micrometer
 * is present. Each half is conditional on its own classes, so an adopter without actuator health
 * or without Micrometer is unaffected.
 *
 * @author Gokhan Demir
 */
@AutoConfiguration(
    after = JwksAutoConfiguration.class,
    // Boot's probes post-processor creates the readiness group at LOWEST_PRECEDENCE; ours must
    // run after it to find the group, which equal precedence and later registration give it.
    afterName = "org.springframework.boot.health.autoconfigure.actuate.endpoint"
        + ".AvailabilityProbesAutoConfiguration")
public class JwksObservabilityAutoConfiguration {

  private JwksObservabilityAutoConfiguration() {
    // Only the nested configurations hold beans.
  }

  @Configuration(proxyBeanMethods = false)
  @ConditionalOnClass(HealthContributor.class)
  @ConditionalOnBooleanProperty("opentmf.security.jwks.readiness")
  static class Readiness {

    @Bean
    @ConditionalOnEnabledHealthIndicator("jwks")
    HealthContributor jwksHealthContributor(TrustedIssuerKeys keys) {
      return new JwksHealthContributor(keys.issuers(), Clock.systemUTC());
    }

    @Bean
    @ConditionalOnEnabledHealthIndicator("jwks")
    HealthEndpointGroupsPostProcessor jwksReadinessGroupPostProcessor(Environment environment) {
      return new JwksReadinessGroupPostProcessor(environment);
    }
  }

  @Configuration(proxyBeanMethods = false)
  @ConditionalOnClass(MeterRegistry.class)
  static class Metrics {

    @Bean
    JwksMetrics jwksMetrics(TrustedIssuerKeys keys) {
      return new JwksMetrics(keys.issuers(), Clock.systemUTC());
    }
  }
}
