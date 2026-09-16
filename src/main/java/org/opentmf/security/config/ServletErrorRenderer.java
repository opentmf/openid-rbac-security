package org.opentmf.security.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Stream;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.util.function.SingletonSupplier;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.ModelAndView;

/**
 * Renders an exception from inside the security filter chain the way the
 * {@code DispatcherServlet} would: through the application's own
 * {@code HandlerExceptionResolver}s, in their order, the first that answers wins — so a
 * {@code @ControllerAdvice}, a {@code ProblemDetail} handler or a TMF-Error renderer answers
 * these the way it answers everything else. A resolver that writes the response (a
 * {@code ResponseEntity}) or asks the container for its error page has rendered; one that
 * returns a view to render cannot be honoured from a filter; and when none answers at all the
 * bare status goes out, with the given headers and an empty body.
 *
 * <p>Shared by every library filter that answers a request itself — the HTTP-status matrix and
 * the signing-key outage — so one authority owns "the body is the application's own".
 *
 * @author Gokhan Demir
 */
@Slf4j
public class ServletErrorRenderer {

  private final Supplier<List<HandlerExceptionResolver>> exceptionResolvers;

  /**
   * Creates the renderer.
   *
   * @param exceptionResolvers supplies the {@code HandlerExceptionResolver}s of the context that
   *     dispatches the requests — the ones its {@code DispatcherServlet} renders exceptions
   *     through. Looked up once, on first use, never eagerly
   */
  public ServletErrorRenderer(Supplier<Stream<HandlerExceptionResolver>> exceptionResolvers) {
    // The dispatcher's own order: the first resolver to answer renders.
    this.exceptionResolvers = SingletonSupplier.of(() ->
        exceptionResolvers.get().sorted(AnnotationAwareOrderComparator.INSTANCE).toList());
  }

  /**
   * Renders the exception, or the bare status when the application does not.
   *
   * @param request the request
   * @param response the response to render into
   * @param status the status to answer with when no resolver renders
   * @param headers headers the bare answer carries; the resolvers set their own
   * @param ex the exception, the one the dispatcher would have raised
   */
  public void render(
      HttpServletRequest request, HttpServletResponse response, HttpStatus status,
      HttpHeaders headers, Exception ex) {
    boolean rendered;
    try {
      rendered = renderedByTheApplication(request, response, ex);
    } catch (RuntimeException | LinkageError rendering) {
      log.debug("The exception resolvers failed; answering {} bare.", status.value(), rendering);
      rendered = false;
    }
    if (!rendered && !response.isCommitted()) {
      response.resetBuffer();
      response.setStatus(status.value());
      headers.forEach((name, values) -> values.forEach(value -> response.addHeader(name, value)));
      response.setContentLength(0);
    }
  }

  private boolean renderedByTheApplication(
      HttpServletRequest request, HttpServletResponse response, Exception ex) {
    for (HandlerExceptionResolver exceptionResolver : exceptionResolvers.get()) {
      ModelAndView resolved = exceptionResolver.resolveException(request, response, null, ex);
      if (resolved != null) {
        if (resolved.isEmpty() || response.isCommitted()) {
          return true;
        }
        log.debug("View '{}' cannot be rendered from the filter chain; answering bare.",
            resolved.getViewName());
        return false;
      }
    }
    return false;
  }
}
