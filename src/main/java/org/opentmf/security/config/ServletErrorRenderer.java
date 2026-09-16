package org.opentmf.security.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
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
   * <p>The exception's own headers ({@code Retry-After} on a signing-key outage) are written to
   * the response <em>before</em> the resolvers run, once: an exception mapper that rebuilds the
   * answer as {@code ResponseEntity.status(body.getStatus()).body(body)} — the shape every DNMS
   * service inherited from the template — carries no headers of its own, and a
   * {@code ResponseEntity} adds its headers to the response without resetting the ones already
   * there. A resolver that copies the exception's headers itself (Spring's default one, with
   * {@code addHeader}, before it {@code sendError}s — after which Tomcat's facade reports the
   * response committed and nothing can be collapsed) sees a response on which adding a value the
   * header already carries is a no-op, so the wire carries each value exactly once.
   *
   * @param request the request
   * @param response the response to render into
   * @param status the status to answer with when no resolver renders
   * @param headers the exception's own headers; on the wire whoever renders
   * @param ex the exception, the one the dispatcher would have raised
   */
  public void render(
      HttpServletRequest request, HttpServletResponse response, HttpStatus status,
      HttpHeaders headers, Exception ex) {
    if (!response.isCommitted()) {
      headers.forEach((name, values) -> {
        response.setHeader(name, values.isEmpty() ? "" : values.get(0));
        for (int i = 1; i < values.size(); i++) {
          response.addHeader(name, values.get(i));
        }
      });
    }
    boolean rendered;
    try {
      rendered = renderedByTheApplication(request, new WriteOnceHeaders(response, headers), ex);
    } catch (RuntimeException | LinkageError rendering) {
      log.debug("The exception resolvers failed; answering {} bare.", status.value(), rendering);
      rendered = false;
    }
    if (!rendered && !response.isCommitted()) {
      response.resetBuffer();
      response.setStatus(status.value());
      response.setContentLength(0);
    }
  }

  /**
   * The response as the resolvers see it: adding a value that one of the exception's headers
   * already carries is a no-op, so a resolver that copies those headers itself does not double
   * them. Everything else goes straight through.
   */
  private static final class WriteOnceHeaders extends HttpServletResponseWrapper {

    private final HttpHeaders exceptionHeaders;

    private WriteOnceHeaders(HttpServletResponse response, HttpHeaders exceptionHeaders) {
      super(response);
      this.exceptionHeaders = exceptionHeaders;
    }

    @Override
    public void addHeader(String name, String value) {
      if (alreadyCarries(name, value)) {
        return;
      }
      super.addHeader(name, value);
    }

    @Override
    public void setHeader(String name, String value) {
      if (alreadyCarries(name, value) && getHeaders(name).size() == 1) {
        return;
      }
      super.setHeader(name, value);
    }

    private boolean alreadyCarries(String name, String value) {
      return exceptionHeaders.containsHeader(name) && getHeaders(name).contains(value);
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
