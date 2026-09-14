package org.opentmf.security.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

/**
 * Gives an authenticated caller's plain {@code OPTIONS} the answer Spring gives it on any
 * mapped path — {@code 200} with the {@code Allow} of {@code HttpOptionsHandler} — when the
 * access rules would otherwise deny it. {@code OPTIONS} cannot be named in a rule, so on a path
 * the rules protect it always falls to the catch-all; a denial there is not an authorization
 * answer about the resource but an artefact of the rules' vocabulary, and the framework's own
 * answer stands in for it. Every other denial goes to the handler this one decorates.
 *
 * <p>Only reached for authenticated callers: Spring Security routes an anonymous denial to the
 * authentication entry point instead, so an anonymous {@code OPTIONS} keeps its {@code 401} and
 * the method set behind a protected path is not read without a token. The authorization
 * decision itself is never revisited — {@code OPTIONS} the application maps itself is left to
 * the decorated handler, as is any path the rules permit, which the framework answers natively.
 *
 * @author Gokhan Demir
 */
@RequiredArgsConstructor
public class OptionsAccessDeniedHandler implements AccessDeniedHandler {

  private final AccessDeniedHandler delegate;
  private final ServletSupportedMethodsResolver resolver;

  @Override
  public void handle(
      HttpServletRequest request, HttpServletResponse response, AccessDeniedException exception)
      throws IOException, ServletException {
    MatrixAnswer answer = answerFor(request);
    if (answer.kind() != MatrixAnswer.Kind.OPTIONS) {
      delegate.handle(request, response, exception);
      return;
    }
    if (response.isCommitted()) {
      return;
    }
    // A filter may have buffered body bytes before the denial surfaced. They would survive
    // these writes and contradict the Content-Length below — Spring's own handler clears them
    // via sendError, which resets the buffer, so this path must reset it too.
    response.resetBuffer();
    response.setHeader(HttpHeaders.ALLOW, EndpointRules.optionsAllowHeader(answer.allow()));
    response.setStatus(HttpServletResponse.SC_OK);
    response.setContentLength(0);
  }

  private MatrixAnswer answerFor(HttpServletRequest request) {
    if (!HttpMethod.OPTIONS.matches(request.getMethod())) {
      return MatrixAnswer.proceed();
    }
    // The matrix filter left what it resolved; only a request that reached this chain some
    // other way has to be looked up now.
    Optional<SupportedMethods> route =
        request.getAttribute(ServletHttpStatusMatrixFilter.ROUTE_ATTRIBUTE)
            instanceof SupportedMethods resolved
            ? Optional.of(resolved)
            : resolver.resolve(request);
    return route.map(supported -> EndpointRules.answerFor(HttpMethod.OPTIONS, supported))
        .orElseGet(MatrixAnswer::proceed);
  }
}
