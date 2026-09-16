package org.opentmf.security.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRegistration;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;
import java.util.stream.Stream;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.util.ClassUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.DispatcherServlet;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.NoHandlerFoundException;

/**
 * Applies the HTTP-status matrix to every request, before authentication and before the access
 * rules: {@code 404} for a path no handler serves, {@code 405} for a method the path does not
 * implement — and only a request whose path and method both exist goes on to earn its
 * {@code 401} or {@code 403}. A plain {@code OPTIONS} on a served path counts as an existing
 * method, since Spring answers it for every mapped path: it goes on like any other, and once
 * the caller has authenticated, {@link OptionsAccessDeniedHandler} gives it Spring's answer.
 *
 * <p>The {@code 404} and {@code 405} bodies are the application's own: the same exceptions the
 * {@code DispatcherServlet} would raise ({@code NoHandlerFoundException},
 * {@code HttpRequestMethodNotSupportedException} — the latter without supported methods, so
 * that no {@code Allow} header is derived from it) are handed to the application's
 * {@code HandlerExceptionResolver}s through {@link ServletErrorRenderer}, exactly as the
 * dispatcher would hand them over. An application with no such handler gets what it would get
 * natively: Spring's default resolver and the container's error page.
 *
 * <p>A request the container dispatches to a servlet other than Spring MVC's, whose routes the
 * handler mappings know nothing about, is not the matrix's to answer and passes straight
 * through. A CORS pre-flight is a plain {@code OPTIONS} here: where the application has
 * configured CORS, Spring's own CORS filter has answered it before this one runs.
 *
 * <p>Never registered as a bean — that would also install it in the servlet container, outside
 * the security chain it belongs to.
 *
 * @author Gokhan Demir
 */
@Slf4j
public class ServletHttpStatusMatrixFilter extends OncePerRequestFilter {

  /**
   * Where a request that proceeds carries what the mappings said about its path, so that a
   * later answer for it — {@link OptionsAccessDeniedHandler}'s — need not ask again.
   */
  public static final String ROUTE_ATTRIBUTE = SupportedMethods.class.getName();

  private final ServletSupportedMethodsResolver resolver;
  private final ServletErrorRenderer renderer;
  private final Map<String, Boolean> dispatcherServlets = new ConcurrentHashMap<>();

  /**
   * Creates the filter.
   *
   * @param resolver answers what the dispatching context serves on a path
   * @param exceptionResolvers supplies the {@code HandlerExceptionResolver}s of the context that
   *     dispatches the requests this filter guards — the ones its {@code DispatcherServlet}
   *     renders exceptions through. Looked up once, on first use, never eagerly
   */
  public ServletHttpStatusMatrixFilter(
      ServletSupportedMethodsResolver resolver,
      Supplier<Stream<HandlerExceptionResolver>> exceptionResolvers) {
    this.resolver = resolver;
    this.renderer = new ServletErrorRenderer(exceptionResolvers);
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    if (!boundForSpringMvc(request)) {
      chain.doFilter(request, response);
      return;
    }
    Optional<SupportedMethods> route = resolver.resolve(request);
    if (route.isEmpty()) {
      chain.doFilter(request, response);
      return;
    }
    MatrixAnswer answer =
        EndpointRules.answerFor(HttpMethod.valueOf(request.getMethod()), route.get());
    switch (answer.kind()) {
      case NOT_FOUND -> renderer.render(request, response, HttpStatus.NOT_FOUND,
          HttpHeaders.EMPTY,
          new NoHandlerFoundException(request.getMethod(), request.getRequestURI(),
              new ServletServerHttpRequest(request).getHeaders()));
      case METHOD_NOT_ALLOWED -> renderer.render(request, response,
          HttpStatus.METHOD_NOT_ALLOWED, HttpHeaders.EMPTY,
          new HttpRequestMethodNotSupportedException(request.getMethod()));
      case PROCEED, OPTIONS -> {
        request.setAttribute(ROUTE_ATTRIBUTE, route.get());
        chain.doFilter(request, response);
      }
    }
  }

  /**
   * Whether the container will hand this request to a {@code DispatcherServlet}. A co-deployed
   * servlet — a console, a SOAP or JAX-RS engine — serves routes the handler mappings cannot see,
   * so its requests are left to the access rules and to it. Without mapping information (a
   * mocked container) the dispatcher is assumed.
   */
  private boolean boundForSpringMvc(HttpServletRequest request) {
    String servletName = request.getHttpServletMapping().getServletName();
    if (!StringUtils.hasText(servletName)) {
      return true;
    }
    return dispatcherServlets.computeIfAbsent(
        servletName, name -> isDispatcherServlet(request.getServletContext(), name));
  }

  private static boolean isDispatcherServlet(ServletContext context, String servletName) {
    try {
      ServletRegistration registration = context.getServletRegistration(servletName);
      if (registration == null || registration.getClassName() == null) {
        return true;
      }
      Class<?> type = ClassUtils.forName(registration.getClassName(), context.getClassLoader());
      return DispatcherServlet.class.isAssignableFrom(type);
    } catch (RuntimeException | ClassNotFoundException | LinkageError ex) {
      log.debug("Could not identify servlet '{}'; assuming Spring MVC.", servletName, ex);
      return true;
    }
  }
}
