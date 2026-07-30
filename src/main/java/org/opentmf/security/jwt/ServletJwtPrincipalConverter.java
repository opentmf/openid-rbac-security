package org.opentmf.security.jwt;

import java.util.List;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;

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
public class ServletJwtPrincipalConverter implements Converter<Jwt, AbstractAuthenticationToken> {

  private final JwtPrincipalExtractor extractor;

  public ServletJwtPrincipalConverter(String primaryClaimName, List<String> fallbackClaimNames,
      GrantedAuthoritiesConverter authoritiesConverter) {
    this.extractor =
        new JwtPrincipalExtractor(primaryClaimName, fallbackClaimNames, authoritiesConverter);
  }

  @Override
  public AbstractAuthenticationToken convert(Jwt jwt) {
    return extractor.token(jwt);
  }
}
