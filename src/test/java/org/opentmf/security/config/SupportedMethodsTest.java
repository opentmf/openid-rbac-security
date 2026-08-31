package org.opentmf.security.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/**
 * @author Gokhan Demir
 */
class SupportedMethodsTest {

  @Test
  void notServed_reportsNoPathAndNoMethods() {
    SupportedMethods notServed = SupportedMethods.notServed();

    assertThat(notServed.pathServed()).isFalse();
    assertThat(notServed.acceptsAnyMethod()).isFalse();
    assertThat(notServed.declared()).isEmpty();
  }

  @Test
  void notServed_isShared() {
    assertThat(SupportedMethods.notServed()).isSameAs(SupportedMethods.notServed());
  }
}
