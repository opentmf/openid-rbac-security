package org.opentmf.security.model;

import jakarta.validation.Valid;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotEmpty;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import lombok.Getter;
import lombok.Setter;
import org.springframework.util.StringUtils;
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
@ConfigurationProperties(prefix = OpenTmfSecurityProperties.PREFIX)
@Validated
public class OpenTmfSecurityProperties {

  /** The configuration prefix; shared with the startup guards that read the raw properties. */
  public static final String PREFIX = "opentmf.security";

  /**
   * The property names of the rule lists whose entries carry a {@code method}. Kept next to the
   * fields they name so that renaming or adding such a list is a one-place change — the startup
   * case guard walks exactly these lists, under {@link #PREFIX} and its management twin.
   */
  public static final List<String> METHOD_RULE_LISTS =
      List.of("allowed-endpoints", "secure-endpoints");

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
   * Single-issuer mode: where the signing keys of the one trusted issuer are fetched from.
   * Mutually exclusive with {@link #getIssuers()} — configure exactly one of the two.
   * <p><strong>Examples:</strong></p>
   * <ul>
   * <li>classpath:local-jwk-set.json</li>
   * <li>http://localhost:8092/realms/rehearsal-realm/protocol/openid-connect/certs</li>
   * <li>file:///path/to/jwk-set.json</li>
   * </ul>
   *
   * <p>In this mode the {@code iss} claim is not checked, matching the behavior of every
   * release before 2.3.0. Use {@link #getIssuers()} to pin issuers explicitly.
   *
   * @see Resource
   * @see Resource#getURL()
   */
  private Resource jwkSetUri;

  /**
   * Multi-issuer mode: the trusted issuers, each with its own signing keys and claim mapping.
   * Mutually exclusive with {@link #getJwkSetUri()}. Empty by default, which selects
   * single-issuer mode.
   *
   * <p>A token is routed to the entry whose {@link IssuerProperties#getIssuer()} equals its
   * {@code iss} claim; a token whose issuer matches no entry — or that carries no {@code iss}
   * at all — is rejected with {@code 401 invalid_token}. There is deliberately no fallback
   * issuer.
   *
   * <p>{@link #getUserClaim()}, {@link #getFallbackUserClaims()} and
   * {@link #getAuthoritiesClaim()} remain valid alongside this list: they act as the defaults
   * that entries inherit when they do not set their own, so the common vocabulary is
   * configured once and only the deviating issuer overrides it.
   */
  private List<@Valid IssuerProperties> issuers = new ArrayList<>();

  /**
   * The claim in the JWT to consider as the user's name. Defaults to "sub" if not specified.
   * In multi-issuer mode this is the default inherited by entries that do not set their own
   * {@link IssuerProperties#getUserClaim()}.
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
   * How to answer a denied main-port request whose path the application serves, but not for
   * the HTTP method that was used. Defaults to
   * {@link UnmatchedMethodResponse#METHOD_NOT_ALLOWED} — the same {@code 405} with an
   * {@code Allow} header that Spring itself would return had the request reached the
   * dispatcher. Set to {@link UnmatchedMethodResponse#DENY} to answer every denial with
   * {@code 403}, as releases before 3.0.0 did.
   */
  private UnmatchedMethodResponse unmatchedMethodResponse =
      UnmatchedMethodResponse.METHOD_NOT_ALLOWED;

  /**
   * Security configuration applied to the actuator management port when
   * {@code management.server.port} differs from {@code server.port}.
   */
  private @Valid Management management = new Management();

  /**
   * Guards the two mutually exclusive ways of declaring trust. Neither configured means the
   * service would accept no token at all; both configured is ambiguous about which issuer
   * governs. Either way the deployer must choose, so boot fails rather than guessing.
   */
  @AssertTrue(message = "Configure exactly one of opentmf.security.jwk-set-uri (single issuer)"
      + " or opentmf.security.issuers (multiple issuers) — currently neither or both are set.")
  public boolean isTrustDeclaredExactlyOnce() {
    return (jwkSetUri != null) != !issuers.isEmpty();
  }

  /**
   * A repeated {@code iss} value would make issuer-to-entry routing ambiguous — the second
   * entry's keys and claim mapping would silently never be used.
   */
  @AssertTrue(message = "Each opentmf.security.issuers[].issuer must be unique;"
      + " duplicate issuer values cannot be routed unambiguously.")
  public boolean isIssuerUnique() {
    return isDistinct(issuers.stream().map(IssuerProperties::getIssuer).toList());
  }

  /**
   * Names only label log output, but duplicates there make those logs unreadable precisely
   * when someone is debugging which issuer accepted a token.
   */
  @AssertTrue(message = "Each opentmf.security.issuers[].name must be unique when set.")
  public boolean isIssuerNameUnique() {
    return isDistinct(issuers.stream()
        .map(IssuerProperties::getName)
        .filter(StringUtils::hasText)
        .toList());
  }

  private static boolean isDistinct(List<String> values) {
    Set<String> seen = new HashSet<>();
    return values.stream().allMatch(seen::add);
  }

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

    /**
     * How to answer a denied management-port request whose path the application serves, but
     * not for the HTTP method that was used. Mirrors the main-port
     * {@code unmatched-method-response} and shares its default,
     * {@link UnmatchedMethodResponse#METHOD_NOT_ALLOWED}. Mostly inert while
     * {@link #otherEndpoints} keeps its {@link OtherEndpoints#AUTHENTICATED} default, since
     * an unmatched request then reaches the actuator and is answered there; it matters when
     * a deployment tightens the management port to {@link OtherEndpoints#DENY}.
     */
    private UnmatchedMethodResponse unmatchedMethodResponse =
      UnmatchedMethodResponse.METHOD_NOT_ALLOWED;
  }
}
