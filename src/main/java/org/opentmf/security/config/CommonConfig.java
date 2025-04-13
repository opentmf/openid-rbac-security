package org.opentmf.security.config;

import java.util.Optional;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.util.StringUtils;

/**
 * @author Gokhan Demir
 */
@NoArgsConstructor(access = AccessLevel.PRIVATE)
final class CommonConfig {

  static String principalClaimName(String configuredPrincipalClaimName) {
    return Optional.ofNullable(configuredPrincipalClaimName)
        .filter(StringUtils::hasText)
        .orElse(JwtClaimNames.SUB);
  }

  static String authoritiesClaimName(String configuredAuthoritiesClaimName) {
    return Optional.ofNullable(configuredAuthoritiesClaimName)
        .filter(StringUtils::hasText)
        .orElse("roles");
  }
}
