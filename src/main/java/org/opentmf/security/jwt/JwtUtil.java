package org.opentmf.security.jwt;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * @author Gokhan Demir
 */
@UtilityClass
@Slf4j
public final class JwtUtil {

  @SuppressWarnings({"unchecked", "rawtypes"})
  public static List<String> extractNestedClaimValuesAsList(Jwt jwt, String claimName) {
    if (jwt == null || claimName == null || claimName.isBlank()) {
      return List.of();
    }

    String[] claimParts = claimName.split("\\.");
    Object deepClaim = jwt.getClaim(claimParts[0]);
    
    // Navigate through nested maps
    for (int i = 0, n = claimParts.length - 1; i < n; i++) {
      if (deepClaim == null) {
        log.warn("Claim name = {} claim part {} does not exist in JWT. ", claimName, i);
        return Collections.emptyList();
      }
      
      if (deepClaim instanceof Map map) {
        // Navigate to the next level
        deepClaim = map.get(claimParts[i + 1]);
      } else {
        // Can't navigate deeper if it's not a Map
        log.warn("Claim name = {} claim part {} is not a Map, cannot navigate to nested claim. Found type: {}",
            claimName, i, deepClaim.getClass().getSimpleName());
        return Collections.emptyList();
      }
    }
    
    // Now process the final claim value
    if (deepClaim == null) {
      log.warn("Claim name = {} does not exist in JWT. ", claimName);
      return Collections.emptyList();
    }
    
    if (deepClaim instanceof String s) {
      return Collections.singletonList(s);
    } else if (deepClaim instanceof Collection c) {
      return c.stream().filter(Objects::nonNull).map(Object::toString).toList();
    } else {
      log.warn("Unexpected class type {} for Claim name = {}. Expected String or Collection.",
          deepClaim.getClass().getSimpleName(), claimName);
      return Collections.emptyList();
    }
  }

  /**
   * Extracts a claim value from the JWT as a String, supporting nested claims using dot notation.
   * <p>
   * This method handles both simple claims (e.g., "email") and nested claims (e.g., "user.email").
   * If the claim value is not a String, it will be converted to a String using toString().
   * </p>
   *
   * @param jwt       the JWT token
   * @param claimName the name of the claim to extract (supports nested claims with dot notation)
   * @return the claim value as a String, or null if not found or empty
   */
  public static String extractClaimValueAsString(Jwt jwt, String claimName) {
    if (jwt == null || claimName == null || claimName.isEmpty()) {
      return null;
    }

    Object claim;
    try {
      claim = resolveClaim(jwt, claimName);
    } catch (Exception e) {
      log.debug("Failed to extract claim '{}' from JWT: {}", claimName, e.getMessage());
      return null;
    }
    return claim == null ? null : scalarToString(claim, claimName);
  }

  /** Resolves a claim, navigating nested maps when the name uses dot notation. */
  private static Object resolveClaim(Jwt jwt, String claimName) {
    if (!claimName.contains(".")) {
      return jwt.getClaim(claimName);
    }
    String[] parts = claimName.split("\\.");
    Object current = jwt.getClaim(parts[0]);
    for (int i = 1; i < parts.length && current != null; i++) {
      if (current instanceof Map<?, ?> map) {
        current = map.get(parts[i]);
      } else {
        return null;
      }
    }
    return current;
  }

  /** Converts a non-null scalar claim to String; rejects collections, arrays, and maps. */
  private static String scalarToString(Object claim, String claimName) {
    if (claim instanceof String string) {
      return string;
    }
    if (claim instanceof Collection<?> collection) {
      throw new IllegalStateException("Claim '" + claimName + "' resolved to a collection ("
          + collection.getClass().getSimpleName() + "), not a scalar.");
    }
    if (claim.getClass().isArray()) {
      throw new IllegalStateException("Claim '" + claimName + "' resolved to an array ("
          + claim.getClass().getSimpleName() + "), not a scalar.");
    }
    if (claim instanceof Map<?, ?>) {
      throw new IllegalStateException(
          "Claim '" + claimName + "' resolved to a Map, not a scalar.");
    }
    return claim.toString();
  }
}
