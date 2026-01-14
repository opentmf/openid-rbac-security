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

    try {
      Object claim;

      // Handle nested claims (e.g., "user.email", "realm_access.client_id")
      if (claimName.contains(".")) {
        String[] parts = claimName.split("\\.");
        Object current = jwt.getClaim(parts[0]);
        for (int i = 1; i < parts.length && current != null; i++) {
          if (current instanceof Map<?, ?> map) {
            current = map.get(parts[i]);
          } else {
            return null;
          }
        }
        claim = current;
      } else {
        // Simple claim
        claim = jwt.getClaim(claimName);
      }

      if (claim == null) {
        return null;
      }

      if (claim instanceof String) {
        return (String) claim;
      } else if (claim instanceof Collection<?> c) {
        throw new IllegalStateException(
            "Claim '" + claimName + "' resolved to a collection (" + c.getClass().getSimpleName() + "), not a scalar.");
      } else if (claim.getClass().isArray()) {
        throw new IllegalStateException(
            "Claim '" + claimName + "' resolved to an array (" + claim.getClass().getSimpleName() + "), not a scalar.");
      } else if (claim instanceof Map<?, ?>) {
        throw new IllegalStateException(
            "Claim '" + claimName + "' resolved to a Map, not a scalar.");
      } else if (claim != null) {
        // Convert other types to String
        return claim.toString();
      }
    } catch (IllegalStateException e) {
      // Re-throw IllegalStateException (for Collections/Arrays/Maps)
      throw e;
    } catch (Exception e) {
      log.debug("Failed to extract claim '{}' from JWT: {}", claimName, e.getMessage());
    }

    return null;
  }
}
