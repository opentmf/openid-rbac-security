package org.opentmf.security.config;

import java.util.List;
import java.util.Optional;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.opentmf.security.model.IssuerProperties;
import org.opentmf.security.model.OpenTmfSecurityProperties;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.util.StringUtils;

/**
 * @author Gokhan Demir
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class CommonConfig {

  private static final String SINGLE_ISSUER_NAME = "single-issuer";

  public static String principalClaimName(String configuredPrincipalClaimName) {
    return Optional.ofNullable(configuredPrincipalClaimName)
        .filter(StringUtils::hasText)
        .orElse(JwtClaimNames.SUB);
  }

  public static String authoritiesClaimName(String configuredAuthoritiesClaimName) {
    return Optional.ofNullable(configuredAuthoritiesClaimName)
        .filter(StringUtils::hasText)
        .orElse("roles");
  }

  /**
   * Flattens the configuration into the list of issuers to trust. An empty
   * {@code opentmf.security.issuers} yields a single entry built from the legacy top-level
   * properties, with no issuer pinned — preserving pre-2.3.0 behavior exactly. Otherwise each
   * entry inherits any claim setting it does not declare from the top-level properties.
   */
  public static List<ResolvedIssuer> resolveIssuers(OpenTmfSecurityProperties properties) {
    if (properties.getIssuers().isEmpty()) {
      return List.of(new ResolvedIssuer(
          SINGLE_ISSUER_NAME,
          null,
          properties.getJwkSetUri(),
          principalClaimName(properties.getUserClaim()),
          fallbackUserClaims(properties.getFallbackUserClaims()),
          authoritiesClaimName(properties.getAuthoritiesClaim()),
          List.of()));
    }
    return properties.getIssuers().stream()
        .map(entry -> resolve(entry, properties))
        .toList();
  }

  private static ResolvedIssuer resolve(IssuerProperties entry,
      OpenTmfSecurityProperties properties) {
    return new ResolvedIssuer(
        StringUtils.hasText(entry.getName()) ? entry.getName() : entry.getIssuer(),
        entry.getIssuer(),
        entry.getJwkSetUri(),
        principalClaimName(inherit(entry.getUserClaim(), properties.getUserClaim())),
        entry.getFallbackUserClaims() != null
            ? List.copyOf(entry.getFallbackUserClaims())
            : fallbackUserClaims(properties.getFallbackUserClaims()),
        authoritiesClaimName(
            inherit(entry.getAuthoritiesClaim(), properties.getAuthoritiesClaim())),
        List.copyOf(entry.getAudiences()));
  }

  private static String inherit(String entryValue, String topLevelValue) {
    return StringUtils.hasText(entryValue) ? entryValue : topLevelValue;
  }

  private static List<String> fallbackUserClaims(List<String> configured) {
    return configured != null ? List.copyOf(configured) : List.of();
  }
}
