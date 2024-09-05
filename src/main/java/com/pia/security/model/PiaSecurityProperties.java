package com.pia.security.model;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import java.util.ArrayList;
import java.util.List;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * The httpMethod and API path list for specifying secure and insecure endpoints.
 *
 * @author Gokhan Demir
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "pia-security")
@Validated
public class PiaSecurityProperties {

  /**
   * The list of httpMethod, path and necessary roles in terms of anyMatch.
   */
  private List<@Valid SecureEndpoint> secureEndpoints = new ArrayList<>();

  /**
   * The list of http method - path duos that will bypass security.
   */
  private List<@Valid Endpoint> allowedEndpoints = new ArrayList<>();

  /**
   * The list of paths that will bypass security.
   */
  private List<@NotEmpty String> whitelist = new ArrayList<>();

  /**
   * Must be a valid URL.
   */
  private @NotNull String jwkSetUri;

  /**
   * The claim in the JWT to consider as the user's name. Defaults to "sub" if not specified.
   */
  private String userClaim;

  /**
   * The claim in the JWT to consider as the role associations. Defaults to "roles" if now
   * specified.
   */
  private String authoritiesClaim;
}
