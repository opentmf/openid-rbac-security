package org.opentmf.security.model;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import java.util.ArrayList;
import java.util.List;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;
import org.springframework.validation.annotation.Validated;

/**
 * The httpMethod and API path list for specifying secure and insecure endpoints.
 *
 * @author Gokhan Demir
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "opentmf.security")
@Validated
public class OpenTmfSecurityProperties {

  /**
   * The list of httpMethod, path and necessary roles in terms of anyMatch.
   */
  private List<@Valid SecureEndpoint> secureEndpoints = new ArrayList<>();

  /**
   * The list of http method - path duos that will bypass security.
   */
  private List<@Valid Endpoint> allowedEndpoints = new ArrayList<>();

  /**
   * The list of paths that will be denied access.
   */
  private List<@NotEmpty String> blacklist = new ArrayList<>();

  /**
   * The list of paths that will bypass security.
   */
  private List<@NotEmpty String> whitelist = new ArrayList<>();

  /**
   * Must be a valid Resource pointer.
   * <p><strong>Examples:</strong></p>
   * <ul>
   * <li>classpath:local-jwk-set.json</li>
   * <li>http://localhost:8092/realms/rehearsal-realm/protocol/openid-connect/certs</li>
   * <li>file:///path/to/jwk-set.json</li>
   * </ul>
   * @see Resource
   * @see Resource#getURL()
   */
  private @NotNull Resource jwkSetUri;

  /**
   * The claim in the JWT to consider as the user's name. Defaults to "sub" if not specified.
   */
  private String userClaim;

  /**
   * Fallback claims to use when the primary user-claim is not present in the JWT token.
   * This is useful for client_credentials grant type where the primary claim (e.g., "email")
   * may not exist. The claims will be tried in order until one is found.
   * <p><strong>Example:</strong></p>
   * <pre>
   * opentmf.security:
   *   user-claim: email
   *   fallback-user-claims: client_id, azp, appid, sub
   * </pre>
   */
  private List<String> fallbackUserClaims = new ArrayList<>();

  /**
   * The claim in the JWT to consider as the role associations. Defaults to "roles" if now
   * specified.
   */
  private String authoritiesClaim;
}
