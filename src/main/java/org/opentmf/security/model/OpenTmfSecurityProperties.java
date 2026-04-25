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

  /**
   * Authorization policy applied to any main-port request not matched by {@link #blacklist},
   * {@link #whitelist}, {@link #allowedEndpoints} or {@link #secureEndpoints}. Defaults to
   * {@link OtherEndpoints#DENY} — preserves the historical hard-coded behavior. Set to
   * {@link OtherEndpoints#AUTHENTICATED} to require any valid JWT for unmatched paths, or
   * {@link OtherEndpoints#ALLOW} to permit them anonymously.
   */
  private OtherEndpoints otherEndpoints = OtherEndpoints.DENY;

  /**
   * Security configuration applied to the actuator management port when
   * {@code management.server.port} differs from {@code server.port}.
   */
  private @Valid Management management = new Management();

  /**
   * Security configuration for the separate management connector. Mirrors the main-port
   * model: same property names ({@code whitelist}, {@code blacklist},
   * {@code allowed-endpoints}, {@code secure-endpoints}), evaluated in the same order, so
   * configuration knowledge transfers directly.
   */
  @Getter
  @Setter
  public static class Management {

    /**
     * Default whitelist. Mirrors what infrastructure typically probes unauthenticated.
     */
    public static final List<String> DEFAULT_WHITELIST =
        List.of("/actuator/health", "/actuator/health/**", "/actuator/info");

    /**
     * Paths on the management port denied for all HTTP methods. Mirrors the main-port
     * {@code blacklist}. Evaluated first.
     */
    private List<@NotEmpty String> blacklist = new ArrayList<>();

    /**
     * Paths on the management port served without authentication. Mirrors the main-port
     * {@code whitelist}. Defaults to the three endpoints infrastructure probes typically
     * hit unauthenticated: {@code /actuator/health}, {@code /actuator/health/**}
     * (liveness/readiness subpaths) and {@code /actuator/info}. Evaluated after
     * {@link #blacklist}.
     */
    private List<@NotEmpty String> whitelist = new ArrayList<>(DEFAULT_WHITELIST);

    /**
     * Method-specific paths on the management port that bypass authentication. Mirrors
     * the main-port {@code allowed-endpoints} model. Useful when only a specific HTTP
     * method on a path should be open (for example, allow {@code GET /actuator/loggers}
     * while keeping {@code POST /actuator/loggers} JWT-protected). Evaluated after
     * {@link #whitelist}.
     */
    private List<@Valid Endpoint> allowedEndpoints = new ArrayList<>();

    /**
     * Method-specific paths on the management port that require specific authorities.
     * Mirrors the main-port {@code secure-endpoints} model. Evaluated after
     * {@link #allowedEndpoints}.
     */
    private List<@Valid SecureEndpoint> secureEndpoints = new ArrayList<>();

    /**
     * Authorization policy applied to any management-port request not matched by
     * {@link #blacklist}, {@link #whitelist}, {@link #allowedEndpoints} or
     * {@link #secureEndpoints}. Defaults to {@link OtherEndpoints#AUTHENTICATED} — any
     * valid JWT is accepted, no role check. The main-port default is
     * {@link OtherEndpoints#DENY}; the management default is more permissive on purpose
     * because actuator endpoints are well-known and consumers usually want every endpoint
     * they exposed via {@code management.endpoints.web.exposure.include} to be reachable
     * with any valid JWT, without enumerating each one.
     */
    private OtherEndpoints otherEndpoints = OtherEndpoints.AUTHENTICATED;
  }
}
