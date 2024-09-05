package com.pia.security.api;


import com.pia.security.exception.CarExistsException;
import com.pia.security.exception.CarNotFoundException;
import com.pia.security.model.ErrorContext;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

/**
 * @author Gokhan Demir
 */
@RestControllerAdvice
class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

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

  private ErrorContext errorContext(String message, int status) {
    var errorContext = new ErrorContext();
    errorContext.setMessage(message);
    errorContext.setStatus(String.valueOf(status));
    return errorContext;
  }
}
