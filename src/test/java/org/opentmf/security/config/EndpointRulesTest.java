package org.opentmf.security.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.EnumSource.Mode;
import org.opentmf.security.model.Endpoint;
import org.opentmf.security.model.EndpointMethod;
import org.springframework.http.HttpMethod;

/**
 * @author Gokhan Demir
 */
class EndpointRulesTest {

  @Test
  void httpMethodsFor_whenGet_alsoCoversHead() {
    assertThat(EndpointRules.httpMethodsFor(endpoint(EndpointMethod.GET)))
        .containsExactly(HttpMethod.GET, HttpMethod.HEAD);
  }

  @ParameterizedTest
  @EnumSource(value = EndpointMethod.class, names = "GET", mode = Mode.EXCLUDE)
  void httpMethodsFor_whenNotGet_coversOnlyThatMethod(EndpointMethod method) {
    assertThat(EndpointRules.httpMethodsFor(endpoint(method)))
        .containsExactly(method.toHttpMethod());
  }

  @Test
  void optionsAllow_whenNothingDeclared_offersEveryMethodButTrace() {
    Set<HttpMethod> allowed = EndpointRules.optionsAllow(Set.of());

    assertThat(allowed).contains(HttpMethod.GET, HttpMethod.HEAD, HttpMethod.OPTIONS);
    assertThat(allowed).doesNotContain(HttpMethod.TRACE);
  }

  @Test
  void optionsAllow_whenGetDeclared_addsHeadAndOptions() {
    assertThat(EndpointRules.optionsAllow(ordered(HttpMethod.GET, HttpMethod.DELETE)))
        .containsExactly(HttpMethod.GET, HttpMethod.DELETE, HttpMethod.HEAD, HttpMethod.OPTIONS);
  }

  @Test
  void optionsAllow_whenGetNotDeclared_doesNotAddHead() {
    assertThat(EndpointRules.optionsAllow(ordered(HttpMethod.POST)))
        .containsExactly(HttpMethod.POST, HttpMethod.OPTIONS);
  }

  @Test
  void allowHeader_joinsWithCommaAndSpace() {
    assertThat(EndpointRules.allowHeader(ordered(HttpMethod.GET, HttpMethod.DELETE)))
        .isEqualTo("GET, DELETE");
  }

  @Test
  void allowHeader_whenEmpty_isEmpty() {
    assertThat(EndpointRules.allowHeader(Set.of())).isEmpty();
  }

  private static Endpoint endpoint(EndpointMethod method) {
    Endpoint endpoint = new Endpoint();
    endpoint.setMethod(method);
    endpoint.setPath("/car");
    return endpoint;
  }

  private static Set<HttpMethod> ordered(HttpMethod... methods) {
    return new LinkedHashSet<>(Arrays.asList(methods));
  }
}
