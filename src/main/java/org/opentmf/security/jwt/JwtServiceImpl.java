package org.opentmf.security.jwt;

import static org.opentmf.security.jwt.JwtUtil.extractNestedClaimValuesAsList;
import static java.util.Optional.ofNullable;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import java.text.ParseException;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;

/**
 * @author Gokhan Demir
 */
@Slf4j
@RequiredArgsConstructor
@Service
public class JwtServiceImpl implements JwtService {

  private static final String TOKEN_VALIDATION_MESSAGE = "Token cannot be null or empty";
  private static final String CLAIM_KEY_VALIDATION_MESSAGE = "Claim key cannot be null or empty";
  private static final String INVALID_TOKEN_MESSAGE = "Invalid token";

  private final JwtDecoder jwtDecoder;

  @Override
  public String getJwtPrincipal(String token) {
    Assert.hasText(token, TOKEN_VALIDATION_MESSAGE);

    return ofNullable(decodeJwt(token))
        .map(Jwt::getSubject)
        .orElseThrow(() -> new InvalidBearerTokenException(INVALID_TOKEN_MESSAGE));
  }

  @Override
  public boolean isExpiredToken(Jwt jwt) {
    return ofNullable(jwt)
        .map(Jwt::getExpiresAt)
        .map(expiresAt -> Instant.now().isAfter(expiresAt))
        .orElse(true);
  }

  @Override
  public boolean isExpiredToken(String token) {
    JWTClaimsSet claimsSet = parseJwt(token);
    Optional<Date> expirationTimeDate = Optional.ofNullable(claimsSet.getExpirationTime());

    return expirationTimeDate
        .map(Date::toInstant)
        .map(expirationTime -> Instant.now().isAfter(expirationTime))
        .orElseThrow(
            () -> new InvalidBearerTokenException("Failed to retrieve expiration time from token"));
  }

  @Override
  public Jwt decodeJwt(final String token) {
    try {
      return this.jwtDecoder.decode(token);
    } catch (BadJwtException badJwtException) {
      log.debug("Failed to authenticate since the JWT was invalid");
      throw new InvalidBearerTokenException(badJwtException.getMessage(), badJwtException);
    } catch (JwtException jwtException) {
      throw new AuthenticationServiceException(jwtException.getMessage(), jwtException);
    }
  }

  @Override
  public List<SimpleGrantedAuthority> getGrantedAuthorities(String token, String claimName) {
    return getClaim(token, jwt -> extractNestedClaimValuesAsList(jwt, claimName))
        .map(claims -> claims.stream()
            .map(SimpleGrantedAuthority::new)
            .toList())
        .orElseGet(Collections::emptyList);
  }

  @Override
  public <T> Optional<T> getClaim(String token, Function<Jwt, T> claimResolver) {
    Assert.hasText(token, TOKEN_VALIDATION_MESSAGE);
    Assert.notNull(claimResolver, "claimResolver cannot be null");
    return ofNullable(decodeJwt(token))
        .map(claimResolver);
  }

  @Override
  public <T> Optional<T> getJwtClaim(String token, String claimName) {
    Assert.hasText(claimName, CLAIM_KEY_VALIDATION_MESSAGE);
    Assert.hasText(token, TOKEN_VALIDATION_MESSAGE);
    JWTClaimsSet claimsSet = parseJwt(token);
    log.debug("Retrieving claim: {} from token", claimName);
    @SuppressWarnings("unchecked")
    T claim = (T) claimsSet.getClaim(claimName);
    return ofNullable(claim);
  }

  private JWTClaimsSet parseJwt(String token) {
    try {
      var parsedJwt = JWTParser.parse(token);
      return parsedJwt.getJWTClaimsSet();
    } catch (ParseException e) {
      log.error("Failed to parse token: {}", e.getMessage());
      throw new InvalidBearerTokenException("Failed to parse token", e);
    }
  }

  @Override
  public List<String> getJwtClaims(String token, String claimName) {
    return getJwtClaim(token, claimName)
        .map(this::convertClaimToList)
        .orElseGet(Collections::emptyList);
  }

  private List<String> convertClaimToList(Object claim) {
    if (claim instanceof List<?> list) {
      return convertListClaimToList(list);
    } else if (claim instanceof String str) {
      return convertStringClaimToList(str);
    } else {
      throw new IllegalArgumentException(
          "Unsupported claim type: " + claim.getClass().getSimpleName());
    }
  }

  private List<String> convertListClaimToList(List<?> list) {
    return list.stream()
        .filter(String.class::isInstance)
        .map(String.class::cast)
        .toList();
  }

  private List<String> convertStringClaimToList(String str) {
    return List.of(str);
  }
}