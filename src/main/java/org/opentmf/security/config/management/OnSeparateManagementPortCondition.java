package org.opentmf.security.config.management;

import org.springframework.boot.actuate.autoconfigure.web.server.ManagementPortType;
import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.boot.autoconfigure.condition.SpringBootCondition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;

/**
 * Activates only when {@code management.server.port} is configured such that Spring Boot
 * spawns a separate child {@code ApplicationContext} for the management connector. This
 * is where the management-port {@code SecurityFilterChain} needs to live.
 *
 * <p>Delegates to Spring Boot's own {@link ManagementPortType#get(org.springframework.core.env.Environment)}
 * so the result matches the framework's own decision about whether a CHILD context exists.
 * When the management port is unset or shares the main connector, the main filter chain
 * already protects actuator and this library's management auto-configuration must stay
 * inert to avoid duplicate filter-chain registration.
 *
 * @author Gokhan Demir
 */
public class OnSeparateManagementPortCondition extends SpringBootCondition {

  @Override
  public ConditionOutcome getMatchOutcome(ConditionContext context, AnnotatedTypeMetadata md) {
    ManagementPortType portType = ManagementPortType.get(context.getEnvironment());
    return switch (portType) {
      case DIFFERENT -> ConditionOutcome.match(
          "management.server.port differs from server.port; separate child context active");
      case SAME -> ConditionOutcome.noMatch(
          "management.server.port equals server.port; management shares the main connector");
      case DISABLED -> ConditionOutcome.noMatch("management.server.port is disabled");
    };
  }
}
