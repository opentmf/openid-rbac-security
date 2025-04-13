package org.opentmf.security.jwt;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
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
    String[] claimParts = claimName.split("\\.");
    Object deepClaim = jwt.getClaim(claimParts[0]);
    for (int i = 0, n = claimParts.length; i < n; i++) {
      if (deepClaim == null) {
        log.warn("Claim name = {} claim part {} does not exist in JWT. ", claimName, i);
        return Collections.emptyList();
      } else if (deepClaim instanceof String s) {
        return Collections.singletonList(s);
      } else if (deepClaim instanceof Collection c) {
        return c.stream().toList();
      } else if (deepClaim instanceof Map map) {
        deepClaim = map.get(claimParts[i + 1]);
      } else {
        log.warn("Unexpected class type {} for Claim name = {} claim part {}",
            deepClaim.getClass().getSimpleName(), claimName, i);
      }
    }
    log.warn("Fallback: Returning empty list for claim values");
    return Collections.emptyList();
  }
}
