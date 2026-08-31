package org.opentmf.security.model;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.Setter;

/**
 * Represents an endpoint with an HttpMethod.
 *
 * @author Gokhan Demir
 */
@Getter
@Setter
public class Endpoint {

  @NotNull
  private EndpointMethod method;

  @NotNull
  @Pattern(regexp = "^/.*", message = "A path must start with /")
  private String path;
}
