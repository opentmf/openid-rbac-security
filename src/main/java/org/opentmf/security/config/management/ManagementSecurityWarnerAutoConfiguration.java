package org.opentmf.security.config.management;

import org.opentmf.security.model.OpenTmfSecurityProperties;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;

/**
 * Registers the {@link ManagementSecurityConfigurationWarner} bean exactly once per
 * application boot, regardless of servlet/reactive stack. Gated on Spring Boot Actuator
 * being on the classpath — without actuator, no warning is meaningful.
 *
 * @author Gokhan Demir
 */
@AutoConfiguration
@EnableConfigurationProperties(OpenTmfSecurityProperties.class)
@ConditionalOnClass(name = "org.springframework.boot.actuate.endpoint.annotation.Endpoint")
public class ManagementSecurityWarnerAutoConfiguration {

  @Bean
  ManagementSecurityConfigurationWarner managementSecurityConfigurationWarner(
      Environment environment, OpenTmfSecurityProperties properties) {
    return new ManagementSecurityConfigurationWarner(environment, properties);
  }
}
