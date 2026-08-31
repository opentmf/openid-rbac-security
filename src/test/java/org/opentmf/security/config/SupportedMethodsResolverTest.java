package org.opentmf.security.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.util.ServletRequestPathUtils;

/**
 * Covers what the resolvers do when there is nothing to consult — the degradation path that has
 * to leave a denial exactly as it was.
 *
 * @author Gokhan Demir
 */
class SupportedMethodsResolverTest {

  @Test
  void servletResolver_withNoHandlerMappings_reportsPathNotServed() {
    var resolver = new ServletSupportedMethodsResolver(Stream::empty);

    assertThat(resolver.resolve(new MockHttpServletRequest("PUT", "/car")).pathServed()).isFalse();
  }

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

    assertThat(resolver.resolve(exchange).pathServed()).isFalse();
  }

}
