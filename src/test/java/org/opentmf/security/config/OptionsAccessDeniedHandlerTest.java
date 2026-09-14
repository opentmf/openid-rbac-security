package org.opentmf.security.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

/**
 * The servlet {@code OPTIONS} decorator: Spring's answer for a plain {@code OPTIONS} the rules
 * denied, every other denial to the delegate, and the matrix filter's route reused when present.
 *
 * @author Gokhan Demir
 */
class OptionsAccessDeniedHandlerTest {

  private final AccessDeniedHandler delegate = mock(AccessDeniedHandler.class);
  private final ServletSupportedMethodsResolver resolver =
      mock(ServletSupportedMethodsResolver.class);
  private final OptionsAccessDeniedHandler handler =
      new OptionsAccessDeniedHandler(delegate, resolver);
  private final MockHttpServletResponse response = new MockHttpServletResponse();
  private final AccessDeniedException denied = new AccessDeniedException("Access Denied");

  @Test
  void deniedOptionsOnAServedPath_answersOkWithSpringsAllow() throws Exception {
    when(resolver.resolve(any())).thenReturn(
        Optional.of(new SupportedMethods(Set.of(HttpMethod.GET, HttpMethod.POST), false)));

    handler.handle(new MockHttpServletRequest("OPTIONS", "/car"), response, denied);

    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getHeader(HttpHeaders.ALLOW)).isEqualTo("GET,HEAD,POST,OPTIONS");
    assertThat(response.getContentAsString()).isEmpty();
    verifyNoInteractions(delegate);
  }

  @Test
  void theRouteTheMatrixFilterLeft_isUsedInsteadOfResolvingAgain() throws Exception {
    MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/car");
    request.setAttribute(
        ServletHttpStatusMatrixFilter.ROUTE_ATTRIBUTE,
        new SupportedMethods(Set.of(HttpMethod.DELETE), false));

    handler.handle(request, response, denied);

    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getHeader(HttpHeaders.ALLOW)).isEqualTo("DELETE,OPTIONS");
    verifyNoInteractions(resolver);
  }

  @Test
  void optionsTheApplicationMapsItself_isLeftToTheDelegate() throws Exception {
    when(resolver.resolve(any()))
        .thenReturn(Optional.of(new SupportedMethods(Set.of(HttpMethod.OPTIONS), false)));
    MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/car");

    handler.handle(request, response, denied);

    verify(delegate).handle(request, response, denied);
    assertThat(response.getHeader(HttpHeaders.ALLOW)).isNull();
  }

  @Test
  void anyOtherMethod_isLeftToTheDelegate_withoutConsultingTheMappings() throws Exception {
    MockHttpServletRequest request = new MockHttpServletRequest("DELETE", "/car/1");

    handler.handle(request, response, denied);

    verify(delegate).handle(request, response, denied);
    verifyNoInteractions(resolver);
  }

  @Test
  void whenTheMappingsCannotBeConsulted_theDenialIsLeftToTheDelegate() throws Exception {
    when(resolver.resolve(any())).thenReturn(Optional.empty());
    MockHttpServletRequest request = new MockHttpServletRequest("OPTIONS", "/car");

    handler.handle(request, response, denied);

    verify(delegate).handle(request, response, denied);
  }
}
