package com.pia.security.exception;

/**
 * @author Gokhan Demir
 */
public class CarNotFoundException extends RuntimeException {

  public CarNotFoundException(String message) {
    super(message);
  }
}
