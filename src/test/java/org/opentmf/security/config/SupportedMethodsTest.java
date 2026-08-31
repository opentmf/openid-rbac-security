package org.opentmf.security.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;

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
  void pathServed_isDerivedFromWhatWasActuallyFound() {
    assertThat(new SupportedMethods(Set.of(HttpMethod.GET), false).pathServed()).isTrue();
    assertThat(new SupportedMethods(Set.of(), true).pathServed()).isTrue();
    assertThat(new SupportedMethods(Set.of(), false).pathServed()).isFalse();
  }

  @Test
  void notServed_isShared() {
    assertThat(SupportedMethods.notServed()).isSameAs(SupportedMethods.notServed());
  }
}
