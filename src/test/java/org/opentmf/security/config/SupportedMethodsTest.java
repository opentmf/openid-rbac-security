package org.opentmf.security.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.LinkedHashSet;
import java.util.List;
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

  /**
   * The handler mappings are consulted through views whose iteration order is salted per JVM
   * run, so the record imposes the canonical {@code HttpMethod.values()} order — every Allow
   * header derived from it must read identically run after run.
   */
  @Test
  void declared_isCanonicalised_soAllowHeadersAreDeterministic() {
    SupportedMethods supported = new SupportedMethods(
        new LinkedHashSet<>(List.of(HttpMethod.DELETE, HttpMethod.GET, HttpMethod.POST)), false);

    assertThat(supported.declared())
        .containsExactly(HttpMethod.GET, HttpMethod.POST, HttpMethod.DELETE);
  }
}
