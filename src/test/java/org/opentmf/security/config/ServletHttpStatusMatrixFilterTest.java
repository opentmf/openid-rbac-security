package org.opentmf.security.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import jakarta.servlet.ServletRegistration;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletMapping;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.servlet.DispatcherServlet;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.NoHandlerFoundException;

/**
 * The servlet matrix filter, cell by cell, with the resolver mocked: which row each answer
 * lands on, that the {@code 404} / {@code 405} go through the application's resolvers, and
 * that a request the filter must not answer — an unresolvable one, one bound for another
 * servlet — passes through untouched.
 *
 * @author Gokhan Demir
 */
class ServletHttpStatusMatrixFilterTest {

  private final ServletSupportedMethodsResolver resolver =
      mock(ServletSupportedMethodsResolver.class);
  private final HandlerExceptionResolver applicationResolver = mock(HandlerExceptionResolver.class);
  private final MockHttpServletResponse response = new MockHttpServletResponse();
  private final MockFilterChain chain = new MockFilterChain();
  private ServletHttpStatusMatrixFilter filter;

  @BeforeEach
  void setUp() {
    filter = new ServletHttpStatusMatrixFilter(resolver, () -> Stream.of(applicationResolver));
  }

  @Test
  void aPathNoHandlerServes_isNotFound_renderedByTheApplication() throws Exception {
    given(SupportedMethods.notServed());
    rendersWithBody("{\"status\":404}");

    filter.doFilter(request("GET", "/nothing"), response, chain);

    assertThat(chain.getRequest()).as("the chain must not continue").isNull();
    assertThat(response.getStatus()).isEqualTo(404);
    assertThat(response.getContentAsString()).isEqualTo("{\"status\":404}");
    verify(applicationResolver)
        .resolveException(any(), any(), any(), any(NoHandlerFoundException.class));
  }

  @Test
  void aMethodThePathDoesNotImplement_isMethodNotAllowed_withoutAllow() throws Exception {
    given(new SupportedMethods(Set.of(HttpMethod.GET), false));
    rendersWithBody("{\"status\":405}");

    filter.doFilter(request("PATCH", "/car"), response, chain);

    assertThat(chain.getRequest()).isNull();
    assertThat(response.getStatus()).isEqualTo(405);
    assertThat(response.getHeader(HttpHeaders.ALLOW)).isNull();
    assertThat(response.getContentAsString()).isEqualTo("{\"status\":405}");
  }

  /** The exception handed over names no supported methods, so no resolver can derive an Allow. */
  @Test
  void theMethodNotAllowedException_carriesNoSupportedMethods() throws Exception {
    given(new SupportedMethods(Set.of(HttpMethod.GET), false));
    var captured = new HttpRequestMethodNotSupportedException[1];
    when(applicationResolver.resolveException(any(), any(), any(), any()))
        .thenAnswer(invocation -> {
          captured[0] = invocation.getArgument(3);
          return new ModelAndView();
        });

    filter.doFilter(request("BREW", "/car"), response, chain);

    assertThat(captured[0].getMethod()).isEqualTo("BREW");
    assertThat(captured[0].getSupportedHttpMethods()).isNull();
    assertThat(captured[0].getHeaders().isEmpty()).isTrue();
  }

  @Test
  void whenNoResolverAnswers_theBareStatusGoesOutWithAnEmptyBody() throws Exception {
    given(SupportedMethods.notServed());
    when(applicationResolver.resolveException(any(), any(), any(), any())).thenReturn(null);

    filter.doFilter(request("GET", "/nothing"), response, chain);

    assertThat(response.getStatus()).isEqualTo(404);
    assertThat(response.getContentLength()).isZero();
    assertThat(response.getContentAsString()).isEmpty();
  }

  @Test
  void anImplementedMethod_proceeds_carryingTheRoute() throws Exception {
    var served = new SupportedMethods(Set.of(HttpMethod.GET), false);
    given(served);
    MockHttpServletRequest request = request("GET", "/car");

    filter.doFilter(request, response, chain);

    assertThat(chain.getRequest()).isNotNull();
    assertThat(request.getAttribute(ServletHttpStatusMatrixFilter.ROUTE_ATTRIBUTE))
        .isSameAs(served);
    verifyNoInteractions(applicationResolver);
  }

  /** {@code OPTIONS} is an existing method here; its answer waits for authentication. */
  @Test
  void plainOptions_proceeds() throws Exception {
    given(new SupportedMethods(Set.of(HttpMethod.GET), false));

    filter.doFilter(request("OPTIONS", "/car"), response, chain);

    assertThat(chain.getRequest()).isNotNull();
    assertThat(response.getHeader(HttpHeaders.ALLOW)).isNull();
  }

  @Test
  void whenTheMappingsCannotBeConsulted_theRequestProceeds_toTheAccessRules() throws Exception {
    when(resolver.resolve(any())).thenReturn(Optional.empty());

    filter.doFilter(request("GET", "/nothing"), response, chain);

    assertThat(chain.getRequest()).isNotNull();
    verifyNoInteractions(applicationResolver);
  }

  @Test
  void aRequestBoundForAnotherServlet_proceeds_withoutConsultingTheMappings() throws Exception {
    MockHttpServletRequest request = new MockHttpServletRequest(
        contextWith("h2", HttpServlet.class), "GET", "/h2-console/login");
    request.setHttpServletMapping(
        new MockHttpServletMapping("/login", "/h2-console/*", "h2", null));

    filter.doFilter(request, response, chain);

    assertThat(chain.getRequest()).isNotNull();
    verifyNoInteractions(resolver);
  }

  @Test
  void aRequestBoundForTheDispatcherServlet_isAnswered() throws Exception {
    given(SupportedMethods.notServed());
    when(applicationResolver.resolveException(any(), any(), any(), any())).thenReturn(null);
    MockHttpServletRequest request = new MockHttpServletRequest(
        contextWith("dispatcherServlet", DispatcherServlet.class), "GET", "/nothing");
    request.setHttpServletMapping(
        new MockHttpServletMapping("/nothing", "/", "dispatcherServlet", null));

    filter.doFilter(request, response, chain);

    assertThat(response.getStatus()).isEqualTo(404);
  }

  private void given(SupportedMethods supported) {
    when(resolver.resolve(any())).thenReturn(Optional.of(supported));
  }

  private void rendersWithBody(String body) {
    when(applicationResolver.resolveException(any(), any(), any(), any()))
        .thenAnswer(invocation -> {
      // The resolvers see the response through the renderer's wrapper, as any resolver would.
      HttpServletResponse target = invocation.getArgument(1);
      Exception ex = invocation.getArgument(3);
      target.setStatus(ex instanceof NoHandlerFoundException ? 404 : 405);
      try {
        target.getOutputStream().write(body.getBytes(StandardCharsets.UTF_8));
      } catch (IOException e) {
        throw new IllegalStateException(e);
      }
      return new ModelAndView();
    });
  }

  private static MockHttpServletRequest request(String method, String path) {
    return new MockHttpServletRequest(method, path);
  }

  private static MockServletContext contextWith(String servletName, Class<?> servletClass) {
    ServletRegistration registration = mock(ServletRegistration.class);
    when(registration.getClassName()).thenReturn(servletClass.getName());
    return new MockServletContext() {
      @Override
      public ServletRegistration getServletRegistration(String name) {
        return servletName.equals(name) ? registration : null;
      }
    };
  }
}
