package org.opentmf.security.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

/**
 * Exercises every branch of the decision the handler makes, without a servlet container.
 *
 * @author Gokhan Demir
 */
class MethodNotAllowedAccessDeniedHandlerTest {

  private static final AccessDeniedException DENIED = new AccessDeniedException("denied");

  private AccessDeniedHandler delegate;
  private ServletSupportedMethodsResolver resolver;
  private MockHttpServletResponse response;

  @BeforeEach
  void setUp() {
    delegate = mock(AccessDeniedHandler.class);
    resolver = mock(ServletSupportedMethodsResolver.class);
    response = new MockHttpServletResponse();
  }

  @Test
  void unimplementedMethodOnServedPath_answersMethodNotAllowed() throws Exception {
    given(new SupportedMethods(methods(HttpMethod.GET, HttpMethod.DELETE), false));

    handler().handle(request("PUT"), response, DENIED);

    assertThat(response.getStatus()).isEqualTo(405);
    assertThat(allow()).containsExactlyInAnyOrder("GET", "DELETE");
    assertThat(response.getContentAsString()).isEmpty();
    verifyNoInteractions(delegate);
  }

  @Test
  void implementedMethod_isLeftToTheDelegate() throws Exception {
    given(new SupportedMethods(methods(HttpMethod.GET, HttpMethod.DELETE), false));

    handler().handle(request("DELETE"), response, DENIED);

    verify(delegate).handle(any(), any(), any());
    assertThat(response.getHeader(HttpHeaders.ALLOW)).isNull();
  }

  @Test
  void headIsTreatedAsGet_soItIsLeftToTheDelegate() throws Exception {
    given(new SupportedMethods(methods(HttpMethod.GET), false));

    handler().handle(request("HEAD"), response, DENIED);

    verify(delegate).handle(any(), any(), any());
  }

  @Test
  void pathNoHandlerServes_isLeftToTheDelegate() throws Exception {
    given(SupportedMethods.notServed());

    handler().handle(request("PUT"), response, DENIED);

    verify(delegate).handle(any(), any(), any());
  }

  @Test
  void mappingThatNamesNoMethod_isLeftToTheDelegate() throws Exception {
    given(new SupportedMethods(Set.of(), true));

    handler().handle(request("PUT"), response, DENIED);

    verify(delegate).handle(any(), any(), any());
  }

  @Test
  void blacklistedPath_isLeftToTheDelegateWithoutConsultingTheMappings() throws Exception {
    MockHttpServletRequest request = request("PUT");
    request.setAttribute(ServletBlacklistDenial.ATTRIBUTE, request.getRequestURI());

    handler().handle(request, response, DENIED);

    verify(delegate).handle(any(), any(), any());
    verifyNoInteractions(resolver);
  }

  @Test
  void options_answersOkWithTheOptionsAllowSet() throws Exception {
    given(new SupportedMethods(methods(HttpMethod.GET, HttpMethod.POST), false));

    handler().handle(request("OPTIONS"), response, DENIED);

    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(allow()).containsExactlyInAnyOrder("GET", "POST", "HEAD", "OPTIONS");
  }

  @Test
  void optionsThatTheApplicationImplementsItself_isLeftToTheDelegate() throws Exception {
    given(new SupportedMethods(methods(HttpMethod.GET, HttpMethod.OPTIONS), false));

    handler().handle(request("OPTIONS"), response, DENIED);

    verify(delegate).handle(any(), any(), any());
  }

  private void given(SupportedMethods supported) {
    when(resolver.resolve(any())).thenReturn(supported);
  }

  private MethodNotAllowedAccessDeniedHandler handler() {
    return new MethodNotAllowedAccessDeniedHandler(delegate, resolver);
  }

  private static MockHttpServletRequest request(String method) {
    return new MockHttpServletRequest(method, "/car/Mercedes");
  }

  private static Set<HttpMethod> methods(HttpMethod... methods) {
    return new LinkedHashSet<>(Arrays.asList(methods));
  }

  private Set<String> allow() {
    String header = response.getHeader(HttpHeaders.ALLOW);
    assertThat(header).isNotNull();
    return Arrays.stream(header.split(",")).map(String::trim).collect(Collectors.toSet());
  }
}
