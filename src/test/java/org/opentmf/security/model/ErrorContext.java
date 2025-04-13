package org.opentmf.security.model;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public final class ErrorContext {

  private String status;
  private String message;
}
