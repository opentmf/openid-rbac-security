package org.opentmf.security.config;

import static org.assertj.core.api.Assertions.assertThat;

import io.micrometer.core.instrument.MeterRegistry;
import org.junit.jupiter.api.Test;
import org.opentmf.security.jwks.JwksMetrics;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.availability.ApplicationAvailabilityAutoConfiguration;
import org.springframework.boot.health.actuate.endpoint.HealthEndpointGroups;
import org.springframework.boot.health.autoconfigure.actuate.endpoint.AvailabilityProbesAutoConfiguration;
import org.springframework.boot.health.autoconfigure.actuate.endpoint.HealthEndpointAutoConfiguration;
import org.springframework.boot.health.autoconfigure.contributor.HealthContributorAutoConfiguration;
import org.springframework.boot.health.autoconfigure.registry.HealthContributorRegistryAutoConfiguration;
import org.springframework.boot.health.contributor.HealthContributor;
import org.springframework.boot.micrometer.metrics.autoconfigure.CompositeMeterRegistryAutoConfiguration;
import org.springframework.boot.micrometer.metrics.autoconfigure.MetricsAutoConfiguration;
import org.springframework.boot.micrometer.metrics.autoconfigure.export.simple.SimpleMetricsExportAutoConfiguration;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;

/**
 * The wiring: nothing changes without the opt-in; with it the {@code jwks} contributor exists and
 * is a member of {@code readiness} when that group exists; Boot's own enabled switch wins; the
 * metrics are bound when Micrometer is present and absent when it is not.
 *
 * @author Gokhan Demir
 */
class JwksObservabilityAutoConfigurationTest {

  private static final String JWK_SET = "opentmf.security.jwk-set-uri=classpath:jwk-set.json";

  private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
      .withConfiguration(AutoConfigurations.of(
          JwksAutoConfiguration.class,
          JwksObservabilityAutoConfiguration.class,
          ApplicationAvailabilityAutoConfiguration.class,
          HealthContributorAutoConfiguration.class,
          HealthContributorRegistryAutoConfiguration.class,
          HealthEndpointAutoConfiguration.class,
          AvailabilityProbesAutoConfiguration.class,
          MetricsAutoConfiguration.class,
          CompositeMeterRegistryAutoConfiguration.class,
          SimpleMetricsExportAutoConfiguration.class))
      .withPropertyValues(JWK_SET, "management.endpoint.health.probes.enabled=true");

  @Test
  void byDefault_noIndicator_andTheReadinessGroupIsUntouched() {
    runner.run(context -> {
      assertThat(context).doesNotHaveBean("jwksHealthContributor");
      HealthEndpointGroups groups = context.getBean(HealthEndpointGroups.class);
      assertThat(groups.get("readiness").isMember("jwks")).isFalse();
    });
  }

  @Test
  void optedIn_theIndicatorExists_andReadinessIncludesIt() {
    runner.withPropertyValues("opentmf.security.jwks.readiness=true").run(context -> {
      assertThat(context).hasBean("jwksHealthContributor");
      assertThat(context.getBean("jwksHealthContributor")).isInstanceOf(HealthContributor.class);
      HealthEndpointGroups groups = context.getBean(HealthEndpointGroups.class);
      assertThat(groups.get("readiness").isMember("jwks")).isTrue();
      assertThat(groups.get("readiness").isMember("readinessState")).isTrue();
      assertThat(groups.get("liveness").isMember("jwks")).isFalse();
    });
  }

  @Test
  void optedIn_withoutAReadinessGroup_theIndicatorStillExists() {
    runner.withPropertyValues(
            "opentmf.security.jwks.readiness=true",
            "management.endpoint.health.probes.enabled=false")
        .run(context -> {
          assertThat(context).hasBean("jwksHealthContributor");
          HealthEndpointGroups groups = context.getBean(HealthEndpointGroups.class);
          assertThat(groups.get("readiness")).isNull();
          assertThat(groups.getPrimary().isMember("jwks")).isTrue();
        });
  }

  @Test
  void bootsOwnEnabledSwitch_wins() {
    runner.withPropertyValues(
            "opentmf.security.jwks.readiness=true", "management.health.jwks.enabled=false")
        .run(context -> {
          assertThat(context).doesNotHaveBean("jwksHealthContributor");
          assertThat(context.getBean(HealthEndpointGroups.class).get("readiness").isMember("jwks"))
              .isFalse();
        });
  }

  @Test
  void withMicrometer_theMetersAreBound_regardlessOfTheOptIn() {
    runner.run(context -> {
      assertThat(context).hasSingleBean(JwksMetrics.class);
      MeterRegistry registry = context.getBean(MeterRegistry.class);
      assertThat(registry.find("opentmf.security.jwks.keys").tag("issuer", "single-issuer").gauge())
          .isNotNull();
      assertThat(registry.find("opentmf.security.jwks.keys.age").gauge()).isNotNull();
      assertThat(registry.find("opentmf.security.jwks.fetch.failures").functionCounter())
          .isNotNull();
    });
  }

  @Test
  void withoutMicrometer_theContextStarts_withoutMeters() {
    new WebApplicationContextRunner()
        .withClassLoader(new FilteredClassLoader("io.micrometer"))
        .withConfiguration(AutoConfigurations.of(
            JwksAutoConfiguration.class, JwksObservabilityAutoConfiguration.class))
        .withPropertyValues(JWK_SET)
        .run(context -> {
          assertThat(context).hasNotFailed();
          assertThat(context).doesNotHaveBean(JwksMetrics.class);
        });
  }
}
