package org.opentmf.security.jwt;

import static org.opentmf.security.jwt.JwtUtil.extractClaimValueAsString;

import java.util.Collection;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

/**
 * Custom JWT principal converter for servlet applications that supports fallback claims for principal extraction.
 * <p>
 * This converter tries the primary claim first, and if it's not found or is null/empty,
 * it tries the fallback claims in order until one is found. If no claim is found,
 * it falls back to the JWT subject ('sub' claim).
 * </p>
 *
 * @author Gokhan Demir
 */
@Slf4j
@RequiredArgsConstructor
public class ServletJwtPrincipalConverter implements Converter<Jwt, AbstractAuthenticationToken> {

  private final String primaryClaimName;
  private final List<String> fallbackClaimNames;
  private final GrantedAuthoritiesConverter authoritiesConverter;

  @Override
  public AbstractAuthenticationToken convert(Jwt jwt) {
    // Extract principal using fallback logic
    String principal = extractPrincipalWithFallback(jwt);
    
    // Extract authorities
    Collection<GrantedAuthority> authorities = authoritiesConverter != null 
        ? authoritiesConverter.convert(jwt)
        : List.of();
    
    return new JwtAuthenticationToken(jwt, authorities, principal);
  }

  /**
   * Extracts the principal from the JWT using the primary claim first, then fallback claims.
   *
   * @param jwt the JWT token
   * @return the principal name, or null if not found
   */
  private String extractPrincipalWithFallback(Jwt jwt) {
    // Try primary claim first
    String principal = extractClaimValueAsString(jwt, primaryClaimName);
    if (principal != null && !principal.isEmpty()) {
      log.trace("Extracted principal from primary claim '{}'", primaryClaimName);
      return principal;
    }

    // Try fallback claims in order
    if (fallbackClaimNames != null && !fallbackClaimNames.isEmpty()) {
      for (String fallbackClaim : fallbackClaimNames) {
        principal = extractClaimValueAsString(jwt, fallbackClaim);
        if (principal != null && !principal.isEmpty()) {
          log.trace("Extracted principal from fallback claim '{}'", fallbackClaim);
          return principal;
        }
      }
    }

    // If no claim found in primary or fallback claims, fall back to JWT subject
    // The 'sub' claim is always present in valid JWTs and provides a meaningful identifier
    String subject = jwt.getSubject();
    if (subject != null && !subject.isEmpty()) {
      log.trace("No principal found in primary or fallback claims, using JWT subject");
      return subject;
    }

    // This should rarely happen as 'sub' is required in valid JWTs
    log.warn("No principal could be extracted from JWT. Tried primary claim '{}', fallback claims: {}, and subject",
        primaryClaimName, fallbackClaimNames);
    return null;
  }
}
