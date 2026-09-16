package org.opentmf.security.config;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.DefaultHandlerExceptionResolver;
import org.springframework.web.server.ResponseStatusException;

/**
 * The exception's own headers reach the wire whoever renders: a resolver that rebuilds the
 * answer without them (the shape of every DNMS service's exception mapper), Spring's default
 * resolver that copies them itself, and the bare fallback.
 *
 * @author Gokhan Demir
 */
class ServletErrorRendererTest {

  private static final ResponseStatusException OUTAGE = outage();

  @Test
  void aResolverThatRebuildsTheAnswerWithoutHeaders_stillSendsRetryAfter() {
    HandlerExceptionResolver headerless = (request, response, handler, ex) -> {
      response.setStatus(503);
      response.setContentType("application/problem+json");
      write(response, "{\"status\":503}");
      return new ModelAndView();
    };
    MockHttpServletResponse response = new MockHttpServletResponse();

    new ServletErrorRenderer(() -> Stream.of(headerless))
        .render(new MockHttpServletRequest(), response, HttpStatus.SERVICE_UNAVAILABLE,
            OUTAGE.getHeaders(), OUTAGE);

    assertThat(response.getStatus()).isEqualTo(503);
    assertThat(response.getContentAsByteArray()).isNotEmpty();
    assertThat(response.getHeaders(HttpHeaders.RETRY_AFTER)).containsExactly("30");
  }

  /**
   * Spring's default resolver copies the headers itself and then {@code sendError}s. The mock
   * response commits on {@code sendError} (Tomcat does not, and the renderer then collapses the
   * value to one), so here the header may carry the value twice — never a different value.
   */
  @Test
  void springsDefaultResolver_whichCopiesTheHeadersItself_neverChangesTheValue() {
    MockHttpServletResponse response = new MockHttpServletResponse();

    new ServletErrorRenderer(() -> Stream.of(new DefaultHandlerExceptionResolver()))
        .render(new MockHttpServletRequest(), response, HttpStatus.SERVICE_UNAVAILABLE,
            OUTAGE.getHeaders(), OUTAGE);

    assertThat(response.getStatus()).isEqualTo(503);
    assertThat(response.getHeaders(HttpHeaders.RETRY_AFTER)).isNotEmpty().containsOnly("30");
  }

  @Test
  void whenNoResolverAnswers_theBareStatusCarriesTheHeaders() {
    MockHttpServletResponse response = new MockHttpServletResponse();

    new ServletErrorRenderer(Stream::empty)
        .render(new MockHttpServletRequest(), response, HttpStatus.SERVICE_UNAVAILABLE,
            OUTAGE.getHeaders(), OUTAGE);

    assertThat(response.getStatus()).isEqualTo(503);
    assertThat(response.getContentLength()).isZero();
    assertThat(response.getHeaders(HttpHeaders.RETRY_AFTER)).containsExactly("30");
  }

  private static ResponseStatusException outage() {
    return new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "keys") {
      @Override
      public HttpHeaders getHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.RETRY_AFTER, "30");
        return headers;
      }
    };
  }

  private static void write(HttpServletResponse response, String body) {
    try {
      response.getOutputStream().write(body.getBytes(StandardCharsets.UTF_8));
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }
}
