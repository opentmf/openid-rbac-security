package org.opentmf.security.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.util.ServletRequestPathUtils;

/**
 * Covers what the resolvers answer at the edges: nothing to consult, and a lookup that fails —
 * the two answers a caller must tell apart, because one is a {@code 404} and the other must
 * leave the request to the access rules. The mappings themselves are exercised on real
 * applications by the matrix ITs.
 *
 * @author Gokhan Demir
 */
class SupportedMethodsResolverTest {

  @Test
  void servletResolver_withNoHandlerMappings_reportsPathNotServed() {
    var resolver = new ServletSupportedMethodsResolver(Stream::empty);

    Optional<SupportedMethods> route = resolver.resolve(new MockHttpServletRequest("PUT", "/car"));

    assertThat(route).isPresent();
    assertThat(route.get().pathServed()).isFalse();
  }

  @Test
  void servletResolver_whenTheLookupFails_reportsNothing_soTheAccessRulesAnswer() {
    var resolver = new ServletSupportedMethodsResolver(() -> {
      throw new IllegalStateException("not ready");
    });

    assertThat(resolver.resolve(new MockHttpServletRequest("PUT", "/car"))).isEmpty();
  }

  /** The probe request carries the parsed path; the real request is never touched. */
  @Test
  void servletResolver_leavesNoParsedPathBehind() {
    var resolver = new ServletSupportedMethodsResolver(Stream::empty);
    MockHttpServletRequest request = new MockHttpServletRequest("PUT", "/car");

    resolver.resolve(request);

    assertThat(ServletRequestPathUtils.hasParsedRequestPath(request)).isFalse();
  }

  @Test
  void reactiveResolver_withNoHandlerMappings_reportsPathNotServed() {
    var resolver = new ReactiveSupportedMethodsResolver(Stream::empty);
    var exchange = MockServerWebExchange.from(MockServerHttpRequest.put("/car"));

    Optional<SupportedMethods> route = resolver.resolve(exchange).block();

    assertThat(route).isPresent();
    assertThat(route.get().pathServed()).isFalse();
  }

  @Test
  void reactiveResolver_whenTheLookupFails_reportsNothing_soTheAccessRulesAnswer() {
    var resolver = new ReactiveSupportedMethodsResolver(() -> {
      throw new IllegalStateException("not ready");
    });
    var exchange = MockServerWebExchange.from(MockServerHttpRequest.put("/car"));

    assertThat(resolver.resolve(exchange).block()).isEmpty();
  }
}
