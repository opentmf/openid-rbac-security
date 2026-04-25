package org.opentmf.security.config.management;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.opentmf.security.model.OpenTmfSecurityProperties;
import org.opentmf.security.model.OpenTmfSecurityProperties.Management;
import org.opentmf.security.model.OtherEndpoints;
import org.springframework.boot.actuate.autoconfigure.web.server.ManagementPortType;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.core.env.Environment;

/**
 * Emits {@code WARN} logs at startup for management-port misconfiguration scenarios.
 * Loaded only when Spring Boot Actuator is on the classpath (its presence is the
 * precondition for any management-port discussion).
 *
 * <p>Three actionable cases are detected:
 *
 * <ol>
 *   <li>Consumer configured {@code opentmf.security.management.*} but the management
 *       port shares the main connector — the block is silently dropped
 *       ({@link #SAME_PORT_BLOCK_IGNORED_WARNING}).
 *   <li>Consumer configured {@code opentmf.security.management.*} but actuator is
 *       disabled entirely via {@code management.server.port: -1} — there are no
 *       endpoints for the block to govern
 *       ({@link #DISABLED_PORT_BLOCK_IGNORED_WARNING}).
 *   <li>Management port is genuinely separate but no {@code opentmf.security.management}
 *       block is configured — library defaults govern, which may surprise consumers
 *       exposing scrapers like {@code /actuator/prometheus}
 *       ({@link #SEPARATE_PORT_DEFAULT_BLOCK_WARNING}).
 * </ol>
 *
 * @author Gokhan Demir
 */
@RequiredArgsConstructor
@Slf4j
public class ManagementSecurityConfigurationWarner {

  static final String SAME_PORT_BLOCK_IGNORED_WARNING =
      "opentmf.security.management.* is configured, but management.server.port is unset or "
          + "equals server.port. The management block is IGNORED because actuator shares the "
          + "main connector. Use opentmf.security.whitelist, secure-endpoints, or "
          + "allowed-endpoints for /actuator/** paths, or set management.server.port to a "
          + "different port to activate the management block.";

  static final String DISABLED_PORT_BLOCK_IGNORED_WARNING =
      "opentmf.security.management.* is configured, but management.server.port is set to a "
          + "negative value (actuator disabled). The management block is IGNORED because no "
          + "actuator endpoints are exposed. Either remove the opentmf.security.management.* "
          + "block, or set management.server.port to a positive value (different from "
          + "server.port) to enable actuator and activate the management block.";

  static final String SEPARATE_PORT_DEFAULT_BLOCK_WARNING =
      "management.server.port differs from server.port (actuator on a separate port), but "
          + "opentmf.security.management.* is not configured. Library defaults apply: "
          + "anonymous access to /actuator/health, /actuator/health/**, /actuator/info; JWT "
          + "required for every other /actuator/** endpoint. If you expose scrapers like "
          + "/actuator/prometheus or /actuator/metrics (via "
          + "management.endpoints.web.exposure.include), add their paths to "
          + "opentmf.security.management.whitelist or configure your scraper to present "
          + "a valid JWT.";

  private final Environment environment;
  private final OpenTmfSecurityProperties properties;

  @EventListener(ApplicationReadyEvent.class)
  public void checkConfiguration() {
    ManagementPortType portType = ManagementPortType.get(environment);
    boolean managementBlockConfigured = managementBlockConfigured();

    switch (portType) {
      case SAME -> {
        if (managementBlockConfigured) {
          log.warn(SAME_PORT_BLOCK_IGNORED_WARNING);
        }
      }
      case DISABLED -> {
        if (managementBlockConfigured) {
          log.warn(DISABLED_PORT_BLOCK_IGNORED_WARNING);
        }
      }
      case DIFFERENT -> {
        if (!managementBlockConfigured) {
          log.warn(SEPARATE_PORT_DEFAULT_BLOCK_WARNING);
        }
      }
    }
  }

  private boolean managementBlockConfigured() {
    Management management = properties.getManagement();
    return !Management.DEFAULT_WHITELIST.equals(management.getWhitelist())
        || !management.getBlacklist().isEmpty()
        || !management.getAllowedEndpoints().isEmpty()
        || !management.getSecureEndpoints().isEmpty()
        || management.getOtherEndpoints() != OtherEndpoints.AUTHENTICATED;
  }
}
