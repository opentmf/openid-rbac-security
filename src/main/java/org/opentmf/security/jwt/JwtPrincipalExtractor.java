package org.opentmf.security.jwt;

import static org.opentmf.security.jwt.JwtUtil.extractClaimValueAsString;

import java.util.Collection;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

/**
 * Shared principal-extraction logic behind {@link ServletJwtPrincipalConverter} and
 * {@link ReactiveJwtPrincipalConverter}: the primary claim is tried first, then the fallback
 * claims in order, then the JWT subject ({@code sub} claim).
 *
 * @author Gokhan Demir
 */
@Slf4j
@RequiredArgsConstructor
class JwtPrincipalExtractor {

  private final String primaryClaimName;
  private final List<String> fallbackClaimNames;
  private final GrantedAuthoritiesConverter authoritiesConverter;

  JwtAuthenticationToken token(Jwt jwt) {
    String principal = extractPrincipalWithFallback(jwt);
    Collection<GrantedAuthority> authorities = authoritiesConverter != null
        ? authoritiesConverter.convert(jwt)
        : List.of();
    return new JwtAuthenticationToken(jwt, authorities, principal);
  }

  private String extractPrincipalWithFallback(Jwt jwt) {
    String principal = extractClaimValueAsString(jwt, primaryClaimName);
    if (principal != null && !principal.isEmpty()) {
      log.trace("Extracted principal from primary claim '{}'", primaryClaimName);
      return principal;
    }

    if (fallbackClaimNames != null && !fallbackClaimNames.isEmpty()) {
      for (String fallbackClaim : fallbackClaimNames) {
        principal = extractClaimValueAsString(jwt, fallbackClaim);
        if (principal != null && !principal.isEmpty()) {
          log.trace("Extracted principal from fallback claim '{}'", fallbackClaim);
          return principal;
        }
      }
    }

    // The 'sub' claim is always present in valid JWTs and provides a meaningful identifier
    String subject = jwt.getSubject();
    if (subject != null && !subject.isEmpty()) {
      log.trace("No principal found in primary or fallback claims, using JWT subject");
      return subject;
    }

    // This should rarely happen as 'sub' is required in valid JWTs
    log.warn("No principal could be extracted from JWT. Tried primary claim '{}', fallback"
            + " claims: {}, and subject",
        primaryClaimName, fallbackClaimNames);
    return null;
  }
}
