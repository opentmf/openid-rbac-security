package org.opentmf.security.jwt;

import com.nimbusds.jwt.JWTParser;
import java.text.ParseException;
import java.util.Map;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

/**
 * Routes a token to the {@link JwtDecoder} of the issuer named in its {@code iss} claim.
 *
 * <p>The filter chains authenticate through an {@code AuthenticationManagerResolver} instead, so
 * this exists for everything that decodes a token outside a chain — notably {@link JwtService}
 * and any consumer injecting the {@code JwtDecoder} bean directly. Without it those callers
 * would be pinned to whichever single issuer's decoder happened to be exposed.
 *
 * <p>The {@code iss} claim is read from the unverified token purely to choose a delegate; the
 * delegate then performs the real signature and claim validation, including pinning that same
 * issuer. An unknown or absent issuer is rejected here — there is no fallback decoder.
 *
 * @author Gokhan Demir
 */
public class CompositeJwtDecoder implements JwtDecoder {

  private final Map<String, JwtDecoder> decodersByIssuer;

  public CompositeJwtDecoder(Map<String, JwtDecoder> decodersByIssuer) {
    this.decodersByIssuer = Map.copyOf(decodersByIssuer);
  }

  @Override
  public Jwt decode(String token) {
    return delegateFor(token).decode(token);
  }

  private JwtDecoder delegateFor(String token) {
    String issuer;
    try {
      issuer = JWTParser.parse(token).getJWTClaimsSet().getIssuer();
    } catch (ParseException e) {
      throw new BadJwtException("Failed to parse the token", e);
    }
    if (issuer == null) {
      throw new BadJwtException("The token carries no iss claim, so no trusted issuer applies");
    }
    JwtDecoder delegate = decodersByIssuer.get(issuer);
    if (delegate == null) {
      throw new BadJwtException("No configured issuer matches the token's iss claim");
    }
    return delegate;
  }
}
