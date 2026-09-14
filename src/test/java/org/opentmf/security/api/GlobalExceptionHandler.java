package org.opentmf.security.api;


import org.opentmf.security.exception.CarExistsException;
import org.opentmf.security.exception.CarNotFoundException;
import org.opentmf.security.model.ErrorContext;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

/**
 * @author Gokhan Demir
 */
@RestControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

  public static final String RENDERER_HEADER = "X-Error-Renderer";
  public static final String RENDERER = "application";

  /**
   * Marks every framework exception this advice renders (a {@code ProblemDetail} for
   * {@code 404} / {@code 405} among them), so a test can tell the application's body from
   * Spring Boot's default one.
   */
  @Override
  protected ResponseEntity<Object> handleExceptionInternal(
      Exception ex, Object body, HttpHeaders headers, HttpStatusCode statusCode,
      WebRequest request) {
    HttpHeaders marked = new HttpHeaders();
    marked.putAll(headers);
    marked.set(RENDERER_HEADER, RENDERER);
    return super.handleExceptionInternal(ex, body, marked, statusCode, request);
  }

  @ExceptionHandler(CarExistsException.class)
  public ResponseEntity<ErrorContext> handle(CarExistsException e) {
    var message = e.getLocalizedMessage();
    return ResponseEntity.status(HttpStatus.CONFLICT.value())
        .body(errorContext(message, HttpStatus.CONFLICT.value()));
  }

  @ExceptionHandler(CarNotFoundException.class)
  public ResponseEntity<ErrorContext> handle(CarNotFoundException e) {
    var message = e.getLocalizedMessage();
    return ResponseEntity.status(HttpStatus.NOT_FOUND.value())
        .body(errorContext(message, HttpStatus.NOT_FOUND.value()));
  }

  /**
   * Only reached when a test config delegates the security entry point to the
   * {@code HandlerExceptionResolver}; the filter chain otherwise handles these before the
   * DispatcherServlet.
   */
  @ExceptionHandler(AuthenticationException.class)
  public ResponseEntity<ErrorContext> handle(AuthenticationException e) {
    var message = e.getLocalizedMessage();
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED.value())
        .body(errorContext(message, HttpStatus.UNAUTHORIZED.value()));
  }

  @ExceptionHandler(AccessDeniedException.class)
  public ResponseEntity<ErrorContext> handle(AccessDeniedException e) {
    var message = e.getLocalizedMessage();
    return ResponseEntity.status(HttpStatus.FORBIDDEN.value())
        .body(errorContext(message, HttpStatus.FORBIDDEN.value()));
  }

  private ErrorContext errorContext(String message, int status) {
    var errorContext = new ErrorContext();
    errorContext.setMessage(message);
    errorContext.setStatus(String.valueOf(status));
    return errorContext;
  }
}
