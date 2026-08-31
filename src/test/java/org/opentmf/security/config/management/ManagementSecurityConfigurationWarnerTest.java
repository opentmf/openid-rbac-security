package org.opentmf.security.config.management;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opentmf.security.model.EndpointMethod;
import org.opentmf.security.model.OpenTmfSecurityProperties;
import org.opentmf.security.model.OpenTmfSecurityProperties.Management;
import org.opentmf.security.model.SecureEndpoint;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;
import org.springframework.mock.env.MockEnvironment;

class ManagementSecurityConfigurationWarnerTest {

  private ListAppender<ILoggingEvent> appender;
  private Logger warnerLogger;

  @BeforeEach
  void setUp() {
    warnerLogger = (Logger) LoggerFactory.getLogger(ManagementSecurityConfigurationWarner.class);
    appender = new ListAppender<>();
    appender.start();
    warnerLogger.addAppender(appender);
  }

  @AfterEach
  void tearDown() {
    warnerLogger.detachAppender(appender);
    appender.stop();
  }

  @Test
  void checkConfiguration_managementPortUnsetWithCustomBlock_emitsIgnoredWarning() {
    Environment env = environment(Map.of());

    OpenTmfSecurityProperties props = new OpenTmfSecurityProperties();
    props.getManagement().getSecureEndpoints().add(secureEndpoint("/actuator/env"));

    new ManagementSecurityConfigurationWarner(env, props).checkConfiguration();

    List<ILoggingEvent> warnings = warningEvents();
    assertEquals(1, warnings.size());
    assertTrue(warnings.get(0).getFormattedMessage()
        .contains(ManagementSecurityConfigurationWarner.SAME_PORT_BLOCK_IGNORED_WARNING));
  }

  @Test
  void checkConfiguration_managementPortExplicitlyEqualToServerPortWithCustomBlock_emitsIgnoredWarning() {
    Environment env = environment(Map.of(
        "server.port", "8080",
        "management.server.port", "8080"));

    OpenTmfSecurityProperties props = new OpenTmfSecurityProperties();
    props.getManagement().getSecureEndpoints().add(secureEndpoint("/actuator/env"));

    new ManagementSecurityConfigurationWarner(env, props).checkConfiguration();

    List<ILoggingEvent> warnings = warningEvents();
    assertEquals(1, warnings.size());
    assertTrue(warnings.get(0).getFormattedMessage()
        .contains(ManagementSecurityConfigurationWarner.SAME_PORT_BLOCK_IGNORED_WARNING));
  }

  @Test
  void checkConfiguration_separatePortWithDefaultBlock_emitsDefaultWarning() {
    Environment env = environment(Map.of(
        "server.port", "8080",
        "management.server.port", "9090"));

    OpenTmfSecurityProperties props = new OpenTmfSecurityProperties();

    new ManagementSecurityConfigurationWarner(env, props).checkConfiguration();

    List<ILoggingEvent> warnings = warningEvents();
    assertEquals(1, warnings.size());
    assertTrue(warnings.get(0).getFormattedMessage()
        .contains(ManagementSecurityConfigurationWarner.SEPARATE_PORT_DEFAULT_BLOCK_WARNING));
  }

  @Test
  void checkConfiguration_samePortWithDefaultBlock_emitsNoWarning() {
    Environment env = environment(Map.of());

    OpenTmfSecurityProperties props = new OpenTmfSecurityProperties();

    new ManagementSecurityConfigurationWarner(env, props).checkConfiguration();

    assertEquals(0, warningEvents().size());
  }

  @Test
  void checkConfiguration_separatePortWithCustomBlock_emitsNoWarning() {
    Environment env = environment(Map.of(
        "server.port", "8080",
        "management.server.port", "9090"));

    OpenTmfSecurityProperties props = new OpenTmfSecurityProperties();
    Management management = props.getManagement();
    management.setWhitelist(List.of("/actuator/health"));
    management.getSecureEndpoints().add(secureEndpoint("/actuator/env"));

    new ManagementSecurityConfigurationWarner(env, props).checkConfiguration();

    assertEquals(0, warningEvents().size());
  }

  @Test
  void checkConfiguration_separatePortWithCustomWhitelist_emitsNoWarning() {
    Environment env = environment(Map.of(
        "server.port", "8080",
        "management.server.port", "9090"));

    OpenTmfSecurityProperties props = new OpenTmfSecurityProperties();
    props.getManagement().setWhitelist(List.of("/actuator/health", "/actuator/prometheus"));

    new ManagementSecurityConfigurationWarner(env, props).checkConfiguration();

    assertEquals(0, warningEvents().size());
  }

  @Test
  void checkConfiguration_managementPortDisabledWithCustomBlock_emitsDisabledWarning() {
    Environment env = environment(Map.of("management.server.port", "-1"));

    OpenTmfSecurityProperties props = new OpenTmfSecurityProperties();
    props.getManagement().getSecureEndpoints().add(secureEndpoint("/actuator/env"));

    new ManagementSecurityConfigurationWarner(env, props).checkConfiguration();

    List<ILoggingEvent> warnings = warningEvents();
    assertEquals(1, warnings.size());
    assertTrue(warnings.get(0).getFormattedMessage()
        .contains(ManagementSecurityConfigurationWarner.DISABLED_PORT_BLOCK_IGNORED_WARNING));
  }

  @Test
  void checkConfiguration_managementPortDisabledWithDefaultBlock_emitsNoWarning() {
    Environment env = environment(Map.of("management.server.port", "-1"));

    OpenTmfSecurityProperties props = new OpenTmfSecurityProperties();

    new ManagementSecurityConfigurationWarner(env, props).checkConfiguration();

    assertEquals(0, warningEvents().size());
  }

  private List<ILoggingEvent> warningEvents() {
    return appender.list.stream().filter(e -> e.getLevel() == Level.WARN).toList();
  }

  private static Environment environment(Map<String, String> properties) {
    MockEnvironment env = new MockEnvironment();
    properties.forEach(env::setProperty);
    return env;
  }

  private static SecureEndpoint secureEndpoint(String path) {
    SecureEndpoint endpoint = new SecureEndpoint();
    endpoint.setMethod(EndpointMethod.GET);
    endpoint.setPath(path);
    endpoint.setRoles(new String[] {"admin"});
    return endpoint;
  }
}
