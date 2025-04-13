package org.opentmf.security.model;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.Setter;
import org.springframework.http.HttpMethod;

/**
 * Represents an endpoint with an HttpMethod.
 *
 * @author Gokhan Demir
 */
@Getter
@Setter
public class Endpoint {

  @NotNull
  private HttpMethod method;

  @NotNull
  @Pattern(regexp = "^/.*", message = "A path must start with /")
  private String path;
}
