package org.opentmf.security.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

/**
 * Turns a denial into {@code 405 Method Not Allowed} when the application serves the request
 * path but not the request's HTTP method, and into {@code 200 OK} for a plain {@code OPTIONS}
 * request. Every other denial is passed to the handler this one decorates.
 *
 * <p>The authorization decision is never revisited: the request was denied and stays denied,
 * and never reaches a controller. Only the status line and the {@code Allow} header differ,
 * so that a caller asking for a method the application does not implement is told so, rather
 * than being told it lacks permission for something that does not exist.
 *
 * <p>The advertised methods come from the application's handler mappings, not from the
 * configured access rules. Access rules are deployment configuration and can omit an endpoint
 * that exists or name one that does not; the code is what the resource actually supports,
 * which is what {@code Allow} is defined to describe. A method the application implements but
 * the access rules withhold therefore stays {@code 403} — that is an authorization answer,
 * and relabelling it would tell the caller the endpoint does not exist when it does.
 *
 * <p>Only reached for authenticated callers. Spring Security routes an anonymous denial to the
 * authentication entry point instead, so an unauthenticated request keeps its {@code 401} and
 * the set of methods an application implements is never disclosed without a token.
 *
 * @author Gokhan Demir
 */
@RequiredArgsConstructor
public class MethodNotAllowedAccessDeniedHandler implements AccessDeniedHandler {

  private final AccessDeniedHandler delegate;
  private final ServletSupportedMethodsResolver resolver;

  @Override
  public void handle(
      HttpServletRequest request, HttpServletResponse response, AccessDeniedException exception)
      throws IOException, ServletException {
    Optional<Set<HttpMethod>> allowed = resolveAllowed(request, exception);
    if (allowed.isEmpty()) {
      delegate.handle(request, response, exception);
      return;
    }
    boolean options = HttpMethod.OPTIONS.matches(request.getMethod());
    response.setHeader(
        HttpHeaders.ALLOW,
        options
            ? EndpointRules.optionsAllowHeader(allowed.get())
            : EndpointRules.allowHeader(allowed.get()));
    response.setStatus(
        options ? HttpServletResponse.SC_OK : HttpServletResponse.SC_METHOD_NOT_ALLOWED);
    response.setContentLength(0);
  }

  /**
   * Returns the methods to advertise, or empty when this denial is none of our business and
   * belongs to the decorated handler.
   */
  private Optional<Set<HttpMethod>> resolveAllowed(
      HttpServletRequest request, AccessDeniedException exception) {
    if (BlacklistDecision.causeOf(exception)) {
      // An explicitly closed path answers uniformly and discloses nothing about itself.
      return Optional.empty();
    }
    return EndpointRules.allowedFor(
        HttpMethod.valueOf(request.getMethod()), resolver.resolve(request));
  }
}
