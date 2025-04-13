package org.opentmf.security.jwt;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * JwtService provides useful methods or clients.
 *
 * @author Gokhan Demir
 */
public interface JwtService {

  /**
   * Retrieves the principal from the provided JWT.
   *
   * @param token the JWT from which to retrieve the principal
   * @return the principal as a String
   */
  String getJwtPrincipal(String token);

  /**
   * Checks if the provided JWT is expired.
   *
   * @param jwt the JWT to check
   * @return true if the JWT is expired, false otherwise
   */
  boolean isExpiredToken(Jwt jwt);

  /**
   * Checks if the provided JWT string is expired. Note: This method does not validate the token, it
   * only checks the expiration time.
   *
   * @param token the JWT string to check
   * @return true if the JWT string is expired, false otherwise
   */
  boolean isExpiredToken(String token);

  /**
   * Decodes the provided JWT string.
   *
   * @param token the JWT string to decode
   * @return the decoded Jwt object
   */
  Jwt decodeJwt(String token);

  /**
   * Retrieves the granted authorities from the provided JWT.
   *
   * @param token    the JWT from which to retrieve the authorities
   * @param claimKey the claim key for the authorities
   * @return a list of SimpleGrantedAuthority objects representing the authorities
   */
  List<SimpleGrantedAuthority> getGrantedAuthorities(String token, String claimKey);

  /**
   * Retrieves a specific claim from the provided JWT.
   *
   * @param token         the JWT from which to retrieve the claim
   * @param claimResolver a function that takes a Jwt object and returns the claim
   * @param <T>           the type of the claim
   * @return an Optional containing the claim if it exists, or an empty Optional if it does not
   */
  <T> Optional<T> getClaim(String token, Function<Jwt, T> claimResolver);

  /**
   * Retrieves a specific claim from the provided JWT. Note: This method does not validate the
   * token, it only extracts the specified claim.
   *
   * @param token     the JWT from which to retrieve the claim
   * @param claimName the name of the claim to retrieve
   * @param <T>       the type of the claim
   * @return an Optional containing the claim if it exists, or an empty Optional if it does not
   */
  <T> Optional<T> getJwtClaim(String token, String claimName);

  /**
   * Retrieves all claims from the provided JWT. Note: This method does not validate the token, it
   * only extracts the claims.
   *
   * @param token    the JWT from which to retrieve the claims
   * @param claimKey the claim key for the claims
   * @return a collection of strings representing the claims
   */
  Collection<String> getJwtClaims(String token, String claimKey);
}