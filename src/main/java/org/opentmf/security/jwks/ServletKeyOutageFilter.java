package org.opentmf.security.jwks;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.opentmf.security.config.ServletErrorRenderer;
import org.springframework.http.HttpStatus;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Answers a bearer request whose issuer's signing keys are unavailable with the typed
 * {@code 503} — from inside the library, before the security entry point can turn anything into
 * a {@code 401} and before the container can turn it into a {@code 500}. Sits before the
 * bearer-token filter, around the rest of the chain: the exception the decorated decoder raises
 * is not an {@code AuthenticationException}, so the bearer filter lets it through untouched, and
 * this filter renders it through the application's own error rendering with {@code Retry-After}.
 *
 * <p>Never registered as a bean — that would also install it in the servlet container.
 *
 * @author Gokhan Demir
 */
@RequiredArgsConstructor
public class ServletKeyOutageFilter extends OncePerRequestFilter {

  private final ServletErrorRenderer renderer;

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    try {
      chain.doFilter(request, response);
    } catch (JwkSetUnavailableException unavailable) {
      renderer.render(request, response, HttpStatus.SERVICE_UNAVAILABLE,
          unavailable.getHeaders(), unavailable);
    }
  }
}
