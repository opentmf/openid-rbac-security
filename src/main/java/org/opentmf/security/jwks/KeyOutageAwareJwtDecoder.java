package org.opentmf.security.jwks;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

/**
 * Decorates one issuer's servlet decoder so that a key-availability failure surfaces as the
 * typed {@link JwkSetUnavailableException} — never as the {@code AuthenticationServiceException}
 * ({@code 500}) or the {@code BadJwtException} ({@code 401}) the undecorated decoder would give
 * a caller whose token cannot be verified for lack of keys. See {@link KeyOutageClassifier}.
 *
 * @author Gokhan Demir
 */
@RequiredArgsConstructor
public class KeyOutageAwareJwtDecoder implements JwtDecoder {

  private final JwtDecoder delegate;
  private final IssuerKeys keys;

  @Override
  public Jwt decode(String token) {
    try {
      return delegate.decode(token);
    } catch (JwtException ex) {
      throw KeyOutageClassifier.classify(ex, keys);
    }
  }
}
