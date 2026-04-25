package org.opentmf.security.config.management;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.mock.env.MockEnvironment;

class OnSeparateManagementPortConditionTest {

  private final OnSeparateManagementPortCondition condition = new OnSeparateManagementPortCondition();

  @Test
  void getMatchOutcome_whenManagementPortUnset_returnsNoMatch() {
    ConditionOutcome outcome = evaluate(Map.of());

    assertFalse(outcome.isMatch());
    assertNotNull(outcome.getMessage());
    assertTrue(outcome.getMessage().contains("equals server.port"));
  }

  @Test
  void getMatchOutcome_whenManagementPortDisabled_returnsNoMatch() {
    ConditionOutcome outcome = evaluate(Map.of("management.server.port", -1));

    assertFalse(outcome.isMatch());
    assertTrue(outcome.getMessage().contains("disabled"));
  }

  @Test
  void getMatchOutcome_whenManagementPortEqualsServerPort_returnsNoMatch() {
    ConditionOutcome outcome = evaluate(Map.of(
        "server.port", 8080,
        "management.server.port", 8080));

    assertFalse(outcome.isMatch());
    assertTrue(outcome.getMessage().contains("equals server.port"));
  }

  @Test
  void getMatchOutcome_whenManagementPortRandom_returnsMatch() {
    ConditionOutcome outcome = evaluate(Map.of("management.server.port", 0));

    assertTrue(outcome.isMatch());
    assertTrue(outcome.getMessage().contains("differs"));
  }

  @Test
  void getMatchOutcome_whenManagementPortDiffersFromServerPort_returnsMatch() {
    ConditionOutcome outcome = evaluate(Map.of(
        "server.port", 8080,
        "management.server.port", 9090));

    assertTrue(outcome.isMatch());
    assertTrue(outcome.getMessage().contains("differs"));
  }

  private ConditionOutcome evaluate(Map<String, Object> properties) {
    MockEnvironment env = new MockEnvironment();
    properties.forEach((k, v) -> env.setProperty(k, String.valueOf(v)));
    ConditionContext ctx = mock(ConditionContext.class);
    when(ctx.getEnvironment()).thenReturn(env);
    AnnotatedTypeMetadata md = mock(AnnotatedTypeMetadata.class);
    return condition.getMatchOutcome(ctx, md);
  }
}
