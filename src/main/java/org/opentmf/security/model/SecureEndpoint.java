package org.opentmf.security.model;

import jakarta.validation.constraints.NotEmpty;
import lombok.Getter;
import lombok.Setter;

/**
 * A secure endpoint consists of a Http Method, path and associated roles. Access will later be
 * granted if at least one client role matches any of the associated roles.
 *
 * @author Gokhan Demir
 */
@Getter
@Setter
public class SecureEndpoint extends Endpoint {

  @NotEmpty
  private String[] roles;
}
