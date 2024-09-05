package com.pia.security.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public final class ErrorContext {

  private String status;
  private String message;
}
