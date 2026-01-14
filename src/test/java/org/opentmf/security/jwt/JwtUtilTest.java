package org.opentmf.security.jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Tests for {@link JwtUtil}.
 */
class JwtUtilTest {

  @Test
  void extractNestedClaimValuesAsList_simpleStringClaim_returnsSingletonList() {
    // Given
    Map<String, Object> claims = Map.of("email", "user@example.com");
    Jwt jwt = createJwt(claims);

    // When
    List<String> result = JwtUtil.extractNestedClaimValuesAsList(jwt, "email");

    // Then
    assertThat(result).containsExactly("user@example.com");
  }

  @Test
  void extractNestedClaimValuesAsList_simpleListClaim_returnsList() {
    // Given
    Map<String, Object> claims = Map.of("roles", Arrays.asList("admin", "user", "guest"));
    Jwt jwt = createJwt(claims);

    // When
    List<String> result = JwtUtil.extractNestedClaimValuesAsList(jwt, "roles");

    // Then
    assertThat(result).containsExactly("admin", "user", "guest");
  }

  @Test
  void extractNestedClaimValuesAsList_nestedClaimWithList_returnsList() {
    // Given
    Map<String, Object> realmAccess = Map.of("roles", Arrays.asList("admin", "user"));
    Map<String, Object> claims = Map.of("realm_access", realmAccess);
    Jwt jwt = createJwt(claims);

    // When
    List<String> result = JwtUtil.extractNestedClaimValuesAsList(jwt, "realm_access.roles");

    // Then
    assertThat(result).containsExactly("admin", "user");
  }

  @Test
  void extractNestedClaimValuesAsList_nestedClaimWithString_returnsSingletonList() {
    // Given
    Map<String, Object> user = Map.of("email", "user@example.com");
    Map<String, Object> claims = Map.of("user", user);
    Jwt jwt = createJwt(claims);

    // When
    List<String> result = JwtUtil.extractNestedClaimValuesAsList(jwt, "user.email");

    // Then
    assertThat(result).containsExactly("user@example.com");
  }

  @Test
  void extractNestedClaimValuesAsList_deeplyNestedClaim_returnsList() {
    // Given
    Map<String, Object> roles = Map.of("values", Arrays.asList("admin", "user"));
    Map<String, Object> access = Map.of("roles", roles);
    Map<String, Object> realm = Map.of("access", access);
    Map<String, Object> claims = Map.of("realm", realm);
    Jwt jwt = createJwt(claims);

    // When
    List<String> result = JwtUtil.extractNestedClaimValuesAsList(jwt, "realm.access.roles.values");

    // Then
    assertThat(result).containsExactly("admin", "user");
  }

  @Test
  void extractNestedClaimValuesAsList_missingClaim_returnsEmptyList() {
    // Given
    Map<String, Object> claims = Collections.emptyMap();
    Jwt jwt = createJwt(claims);

    // When
    List<String> result = JwtUtil.extractNestedClaimValuesAsList(jwt, "nonexistent");

    // Then
    assertThat(result).isEmpty();
  }

  @Test
  void extractNestedClaimValuesAsList_missingNestedClaim_returnsEmptyList() {
    // Given
    Map<String, Object> claims = Map.of("realm_access", Map.of("other", "value"));
    Jwt jwt = createJwt(claims);

    // When
    List<String> result = JwtUtil.extractNestedClaimValuesAsList(jwt, "realm_access.roles");

    // Then
    assertThat(result).isEmpty();
  }

  @Test
  void extractNestedClaimValuesAsList_nestedClaimWithNullValue_returnsEmptyList() {
    // Given
    Map<String, Object> realmAccess = new HashMap<>();
    realmAccess.put("roles", null);
    Map<String, Object> claims = Map.of("realm_access", realmAccess);
    Jwt jwt = createJwt(claims);

    // When
    List<String> result = JwtUtil.extractNestedClaimValuesAsList(jwt, "realm_access.roles");

    // Then
    assertThat(result).isEmpty();
  }

  @Test
  void extractNestedClaimValuesAsList_nestedClaimWithNonMapIntermediate_returnsEmptyList() {
    // Given
    Map<String, Object> claims = Map.of("realm_access", "not-a-map");
    Jwt jwt = createJwt(claims);

    // When
    List<String> result = JwtUtil.extractNestedClaimValuesAsList(jwt, "realm_access.roles");

    // Then
    assertThat(result).isEmpty();
  }

  @Test
  void extractNestedClaimValuesAsList_emptyListClaim_returnsEmptyList() {
    // Given
    Map<String, Object> claims = Map.of("roles", Collections.emptyList());
    Jwt jwt = createJwt(claims);

    // When
    List<String> result = JwtUtil.extractNestedClaimValuesAsList(jwt, "roles");

    // Then
    assertThat(result).isEmpty();
  }

  @Test
  void extractNestedClaimValuesAsList_nestedClaimWithEmptyList_returnsEmptyList() {
    // Given
    Map<String, Object> realmAccess = Map.of("roles", Collections.emptyList());
    Map<String, Object> claims = Map.of("realm_access", realmAccess);
    Jwt jwt = createJwt(claims);

    // When
    List<String> result = JwtUtil.extractNestedClaimValuesAsList(jwt, "realm_access.roles");

    // Then
    assertThat(result).isEmpty();
  }

  @Test
  void extractNestedClaimValuesAsList_nullDuringNavigation_returnsEmptyList() {
    // Given
    Map<String, Object> level1 = new HashMap<>();
    level1.put("level2", null);
    Map<String, Object> claims = Map.of("level1", level1);
    Jwt jwt = createJwt(claims);

    // When
    List<String> result = JwtUtil.extractNestedClaimValuesAsList(jwt, "level1.level2.level3");

    // Then
    assertThat(result).isEmpty();
  }

  @Test
  void extractNestedClaimValuesAsList_collectionDuringNavigation_returnsEmptyList() {
    // Given
    Map<String, Object> claims = Map.of("level1", Arrays.asList("item1", "item2"));
    Jwt jwt = createJwt(claims);

    // When
    List<String> result = JwtUtil.extractNestedClaimValuesAsList(jwt, "level1.level2");

    // Then
    assertThat(result).isEmpty();
  }

  @Test
  void extractNestedClaimValuesAsList_stringDuringNavigation_returnsEmptyList() {
    // Given
    Map<String, Object> claims = Map.of("level1", "not-a-map");
    Jwt jwt = createJwt(claims);

    // When
    List<String> result = JwtUtil.extractNestedClaimValuesAsList(jwt, "level1.level2");

    // Then
    assertThat(result).isEmpty();
  }

  @Test
  void extractNestedClaimValuesAsList_finalValueIsNotStringOrCollection_returnsEmptyList() {
    // Given
    Map<String, Object> claims = Map.of("number", 12345);
    Jwt jwt = createJwt(claims);

    // When
    List<String> result = JwtUtil.extractNestedClaimValuesAsList(jwt, "number");

    // Then
    assertThat(result).isEmpty();
  }

  @Test
  void extractNestedClaimValuesAsList_collectionWithNonStringElements_convertsToString() {
    // Given
    Map<String, Object> claims = Map.of("mixed", Arrays.asList(123, "text", true, 456L));
    Jwt jwt = createJwt(claims);

    // When
    List<String> result = JwtUtil.extractNestedClaimValuesAsList(jwt, "mixed");

    // Then
    assertThat(result).containsExactly("123", "text", "true", "456");
  }

  @Test
  void extractNestedClaimValuesAsList_nestedNullIntermediate_returnsEmptyList() {
    // Given
    Map<String, Object> level1 = new HashMap<>();
    level1.put("level2", null);
    Map<String, Object> claims = Map.of("level1", level1);
    Jwt jwt = createJwt(claims);

    // When
    List<String> result = JwtUtil.extractNestedClaimValuesAsList(jwt, "level1.level2.level3");

    // Then
    assertThat(result).isEmpty();
  }

  // Tests for extractNestedClaimValuesAsList - additional edge cases

  @Test
  void extractNestedClaimValuesAsList_nullJwt_returnsEmptyList() {
    // Given
    Jwt jwt = null;

    // When
    List<String> result = JwtUtil.extractNestedClaimValuesAsList(jwt, "email");

    // Then
    assertThat(result).isEmpty();
  }

  @Test
  void extractNestedClaimValuesAsList_nullClaimName_returnsEmptyList() {
    // Given
    Jwt jwt = createJwt(Map.of("email", "user@example.com"));

    // When
    List<String> result = JwtUtil.extractNestedClaimValuesAsList(jwt, null);

    // Then
    assertThat(result).isEmpty();
  }

  @Test
  void extractNestedClaimValuesAsList_blankClaimName_returnsEmptyList() {
    // Given
    Jwt jwt = createJwt(Map.of("email", "user@example.com"));

    // When
    List<String> result1 = JwtUtil.extractNestedClaimValuesAsList(jwt, "");
    List<String> result2 = JwtUtil.extractNestedClaimValuesAsList(jwt, "   ");

    // Then
    assertThat(result1).isEmpty();
    assertThat(result2).isEmpty();
  }

  @Test
  void extractNestedClaimValuesAsList_claimNameStartsWithDot_returnsEmptyList() {
    // Given
    Jwt jwt = createJwt(Map.of("email", "user@example.com"));

    // When - Tests line 25: claimParts[0].isBlank() branch (when claimParts.length == 0 is false)
    // ".email" splits to ["", "email"] - first part is empty string, which is blank
    List<String> result1 = JwtUtil.extractNestedClaimValuesAsList(jwt, ".email");
    // "  .email" splits to ["  ", "email"] - first part is "  " which is blank
    List<String> result2 = JwtUtil.extractNestedClaimValuesAsList(jwt, "  .email");
    // "\t.email" splits to ["\t", "email"] - first part is "\t" which is blank
    List<String> result3 = JwtUtil.extractNestedClaimValuesAsList(jwt, "\t.email");

    // Then
    assertThat(result1).isEmpty();
    assertThat(result2).isEmpty();
    assertThat(result3).isEmpty();
  }

  @Test
  void extractNestedClaimValuesAsList_claimNameWithOnlyWhitespaceFirstPart_returnsEmptyList() {
    // Given
    Jwt jwt = createJwt(Map.of("email", "user@example.com"));

    // When - Test claimName that splits to have blank first part (tests line 25: claimParts[0].isBlank())
    // " .email" splits to [" ", "email"] - first part is " " which is blank
    List<String> result = JwtUtil.extractNestedClaimValuesAsList(jwt, " .email");

    // Then
    assertThat(result).isEmpty();
  }

  @Test
  void extractNestedClaimValuesAsList_claimNameWithNormalFirstPart_doesNotTriggerBlankCheck() {
    // Given - Test the case where claimParts.length == 0 is false AND claimParts[0].isBlank() is also false
    // This tests the "both false" branch of line 25: if (claimParts.length == 0 || claimParts[0].isBlank())
    // For JaCoCo branch coverage, we need to explicitly test:
    // - claimParts.length == 0 evaluates to false (always true, but needs explicit test)
    // - claimParts[0].isBlank() evaluates to false
    // - The condition evaluates to false and code continues (doesn't return early)
    Map<String, Object> claims = Map.of("email", "user@example.com");
    Jwt jwt = createJwt(claims);

    // When - Normal claim name where:
    // - claimParts.length == 0 is false (split always returns at least one element, so length > 0)
    // - claimParts[0].isBlank() is false (first part is "email", not blank)
    // This ensures the condition on line 25 evaluates to false and code continues (doesn't return early)
    List<String> result = JwtUtil.extractNestedClaimValuesAsList(jwt, "email");

    // Then - Should work normally (tests the "both false" branch of line 25)
    // This explicitly covers the branch where claimParts.length == 0 is false
    assertThat(result).containsExactly("user@example.com");
  }

  @Test
  void extractNestedClaimValuesAsList_claimNameWithNonBlankFirstPart_continuesExecution() {
    // Given - Test explicitly that when claimParts[0] is NOT blank, the condition on line 25 is false
    // and execution continues past the early return
    Map<String, Object> level1 = Map.of("level2", "value");
    Map<String, Object> claims = Map.of("level1", level1);
    Jwt jwt = createJwt(claims);

    // When - Nested claim where first part "level1" is not blank
    // This ensures: claimParts.length > 0 (false for length==0) AND claimParts[0].isBlank() is false
    // So the condition on line 25 is false, and we continue to process the nested claim
    List<String> result = JwtUtil.extractNestedClaimValuesAsList(jwt, "level1.level2");

    // Then - Should successfully extract the nested value (proving we passed line 25's check)
    assertThat(result).containsExactly("value");
  }

  @Test
  void extractNestedClaimValuesAsList_claimNameWithMultipleParts_explicitlyTestsLengthNotZero() {
    // Given - Test explicitly that claimParts.length == 0 evaluates to false
    // This tests the branch on line 25 where claimParts.length == 0 is false
    // We use a claim name with multiple parts to ensure length > 0
    Map<String, Object> level2 = Map.of("level3", "value");
    Map<String, Object> level1 = Map.of("level2", level2);
    Map<String, Object> claims = Map.of("level1", level1);
    Jwt jwt = createJwt(claims);

    // When - Claim name with multiple parts "level1.level2.level3"
    // This ensures: claimParts.length == 3 (so claimParts.length == 0 is explicitly false)
    // AND claimParts[0].isBlank() is false (first part is "level1", not blank)
    // So the condition on line 25 evaluates to false and code continues
    List<String> result = JwtUtil.extractNestedClaimValuesAsList(jwt, "level1.level2.level3");

    // Then - Should successfully extract the deeply nested value
    // This explicitly covers the branch where claimParts.length == 0 evaluates to false
    assertThat(result).containsExactly("value");
  }

  @Test
  void extractNestedClaimValuesAsList_claimNameWithEmptyMiddlePart_testsBranchCoverage() {
    // Given - Test case with empty string in middle: "level1..level3"
    // This splits to ["level1", "", "level3"]
    // claimParts[0] is "level1" (not blank), so claimParts[0].isBlank() is false
    // claimParts.length is 3 (not 0), so claimParts.length == 0 is false
    // This tests a specific branch combination on line 25
    Map<String, Object> level3 = Map.of("value", "result");
    Map<String, Object> level1 = Map.of("level3", level3);
    Map<String, Object> claims = Map.of("level1", level1);
    Jwt jwt = createJwt(claims);

    // When - Claim name with empty middle part "level1..level3"
    // This ensures: claimParts.length == 3 (so claimParts.length == 0 is false)
    // AND claimParts[0] is "level1" (so claimParts[0].isBlank() is false)
    // So the condition on line 25 evaluates to false and code continues
    // (The empty string in the middle will be handled later in the navigation loop)
    List<String> result = JwtUtil.extractNestedClaimValuesAsList(jwt, "level1..level3");

    // Then - Should handle the empty middle part and return empty list
    // This explicitly tests the branch where both conditions are false on line 25
    assertThat(result).isEmpty();
  }

  @Test
  void extractNestedClaimValuesAsList_collectionWithNullElements_filtersNulls() {
    // Given - Collection with null elements to test filter(Objects::nonNull)
    Map<String, Object> claims = Map.of("roles", Arrays.asList("admin", null, "user", null, "guest"));
    Jwt jwt = createJwt(claims);

    // When
    List<String> result = JwtUtil.extractNestedClaimValuesAsList(jwt, "roles");

    // Then - null elements should be filtered out
    assertThat(result).containsExactly("admin", "user", "guest");
  }

  @Test
  void extractNestedClaimValuesAsList_nestedCollectionWithNullElements_filtersNulls() {
    // Given
    Map<String, Object> realmAccess = Map.of("roles", Arrays.asList("admin", null, "user"));
    Map<String, Object> claims = Map.of("realm_access", realmAccess);
    Jwt jwt = createJwt(claims);

    // When
    List<String> result = JwtUtil.extractNestedClaimValuesAsList(jwt, "realm_access.roles");

    // Then
    assertThat(result).containsExactly("admin", "user");
  }

  @Test
  void extractNestedClaimValuesAsList_collectionWithOnlyNullElements_returnsEmptyList() {
    // Given
    Map<String, Object> claims = Map.of("roles", Arrays.asList((String) null, null));
    Jwt jwt = createJwt(claims);

    // When
    List<String> result = JwtUtil.extractNestedClaimValuesAsList(jwt, "roles");

    // Then
    assertThat(result).isEmpty();
  }

  // Tests for extractClaimValueAsString

  @Test
  void extractClaimValueAsString_nullJwt_returnsNull() {
    // Given
    Jwt jwt = null;

    // When
    String result = JwtUtil.extractClaimValueAsString(jwt, "email");

    // Then
    assertThat(result).isNull();
  }

  @Test
  void extractClaimValueAsString_nullClaimName_returnsNull() {
    // Given
    Jwt jwt = createJwt(Map.of("email", "user@example.com"));

    // When
    String result = JwtUtil.extractClaimValueAsString(jwt, null);

    // Then
    assertThat(result).isNull();
  }

  @Test
  void extractClaimValueAsString_emptyClaimName_returnsNull() {
    // Given
    Jwt jwt = createJwt(Map.of("email", "user@example.com"));

    // When
    String result = JwtUtil.extractClaimValueAsString(jwt, "");

    // Then
    assertThat(result).isNull();
  }

  @Test
  void extractClaimValueAsString_whitespaceClaimName_returnsNull() {
    // Given
    Jwt jwt = createJwt(Map.of("email", "user@example.com"));

    // When
    String result = JwtUtil.extractClaimValueAsString(jwt, "   ");

    // Then
    assertThat(result).isNull();
  }

  @Test
  void extractClaimValueAsString_claimNameWithEmptyParts_returnsNull() {
    // Given - Need a Map structure so the empty key check is reached (tests line 104)
    Map<String, Object> level1 = Map.of("level2", "value");
    Map<String, Object> claims = Map.of("level1", level1);
    Jwt jwt = createJwt(claims);

    // When - "level1..level2" splits to ["level1", "", "level2"]
    // Loop: i=1, current is Map level1, key="", so line 104: if (key.isEmpty()) return null;
    String result1 = JwtUtil.extractClaimValueAsString(jwt, "level1..level2");

    // Then - Should return null due to empty key check at line 104
    assertThat(result1).isNull();
  }

  @Test
  void extractClaimValueAsString_nestedPathWithEmptyKeyInMiddle_returnsNull() {
    // Given - Test when a key in the middle of a nested path is empty (tests line 104)
    Map<String, Object> level2 = Map.of("level3", "value");
    Map<String, Object> level1 = Map.of("level2", level2);
    Map<String, Object> claims = Map.of("level1", level1);
    Jwt jwt = createJwt(claims);

    // When - "level1..level2.level3" splits to ["level1", "", "level2", "level3"]
    // At i=1, key="" (empty), so line 104: key.isEmpty() should return null
    String result = JwtUtil.extractClaimValueAsString(jwt, "level1..level2.level3");

    // Then - Should return null due to empty key check at line 104
    assertThat(result).isNull();
  }



  @Test
  void extractClaimValueAsString_claimNameStartsWithDot_returnsNull() {
    // Given
    Jwt jwt = createJwt(Map.of("email", "user@example.com"));

    // When - Tests line 89: parts[0].isBlank() branch
    String result1 = JwtUtil.extractClaimValueAsString(jwt, ".email");
    String result2 = JwtUtil.extractClaimValueAsString(jwt, "  .email");  // whitespace before dot
    String result3 = JwtUtil.extractClaimValueAsString(jwt, "\t.email");  // tab before dot

    // Then
    assertThat(result1).isNull();
    assertThat(result2).isNull();
    assertThat(result3).isNull();
  }

  @Test
  void extractClaimValueAsString_claimNameWithWhitespaceFirstPart_returnsNull() {
    // Given
    Jwt jwt = createJwt(Map.of("email", "user@example.com"));

    // When - Test claimName that splits to have blank first part (tests line 89: parts[0].isBlank())
    String result = JwtUtil.extractClaimValueAsString(jwt, " .email");

    // Then
    assertThat(result).isNull();
  }

  @Test
  void extractClaimValueAsString_claimNameWithOnlyDots_returnsNull() {
    // Given
    Jwt jwt = createJwt(Map.of("email", "user@example.com"));

    // When - Test edge cases with only dots
    String result1 = JwtUtil.extractClaimValueAsString(jwt, "...");
    String result2 = JwtUtil.extractClaimValueAsString(jwt, "..");

    // Then
    assertThat(result1).isNull();
    assertThat(result2).isNull();
  }

  @Test
  void extractClaimValueAsString_nestedPathWithNullInMiddle_returnsNull() {
    // Given - Test when current becomes null during loop iteration
    Map<String, Object> level1 = new HashMap<>();
    level1.put("level2", null);
    Map<String, Object> claims = Map.of("level1", level1);
    Jwt jwt = createJwt(claims);

    // When - Loop should exit early when current is null
    String result = JwtUtil.extractClaimValueAsString(jwt, "level1.level2.level3");

    // Then
    assertThat(result).isNull();
  }

  @Test
  void extractClaimValueAsString_nestedPathWithNonMapIntermediate_returnsNull() {
    // Given - Test when intermediate is not a Map
    Map<String, Object> claims = Map.of("level1", "not-a-map");
    Jwt jwt = createJwt(claims);

    // When
    String result = JwtUtil.extractClaimValueAsString(jwt, "level1.level2");

    // Then
    assertThat(result).isNull();
  }

  @Test
  void extractClaimValueAsString_nestedPathWithIntegerIntermediate_returnsNull() {
    // Given
    Map<String, Object> claims = Map.of("level1", 123);
    Jwt jwt = createJwt(claims);

    // When
    String result = JwtUtil.extractClaimValueAsString(jwt, "level1.level2");

    // Then
    assertThat(result).isNull();
  }

  @Test
  void extractClaimValueAsString_nestedPathWithBooleanIntermediate_returnsNull() {
    // Given
    Map<String, Object> claims = Map.of("level1", true);
    Jwt jwt = createJwt(claims);

    // When
    String result = JwtUtil.extractClaimValueAsString(jwt, "level1.level2");

    // Then
    assertThat(result).isNull();
  }

  @Test
  void extractClaimValueAsString_nestedPathWithCollectionIntermediate_returnsNull() {
    // Given
    Map<String, Object> claims = Map.of("level1", Arrays.asList("a", "b"));
    Jwt jwt = createJwt(claims);

    // When
    String result = JwtUtil.extractClaimValueAsString(jwt, "level1.level2");

    // Then
    assertThat(result).isNull();
  }

  @Test
  void extractClaimValueAsString_simpleStringClaim_returnsString() {
    // Given
    Map<String, Object> claims = Map.of("email", "user@example.com");
    Jwt jwt = createJwt(claims);

    // When
    String result = JwtUtil.extractClaimValueAsString(jwt, "email");

    // Then
    assertThat(result).isEqualTo("user@example.com");
  }

  @Test
  void extractClaimValueAsString_simpleNonStringClaim_convertsToString() {
    // Given
    Map<String, Object> claims = Map.of("number", 12345, "boolean", true, "long", 999L);
    Jwt jwt = createJwt(claims);

    // When
    String numberResult = JwtUtil.extractClaimValueAsString(jwt, "number");
    String booleanResult = JwtUtil.extractClaimValueAsString(jwt, "boolean");
    String longResult = JwtUtil.extractClaimValueAsString(jwt, "long");

    // Then
    assertThat(numberResult).isEqualTo("12345");
    assertThat(booleanResult).isEqualTo("true");
    assertThat(longResult).isEqualTo("999");
  }

  @Test
  void extractClaimValueAsString_nestedStringClaim_returnsString() {
    // Given
    Map<String, Object> user = Map.of("email", "user@example.com");
    Map<String, Object> claims = Map.of("user", user);
    Jwt jwt = createJwt(claims);

    // When
    String result = JwtUtil.extractClaimValueAsString(jwt, "user.email");

    // Then
    assertThat(result).isEqualTo("user@example.com");
  }

  @Test
  void extractClaimValueAsString_nestedNonStringClaim_convertsToString() {
    // Given
    Map<String, Object> user = Map.of("id", 12345);
    Map<String, Object> claims = Map.of("user", user);
    Jwt jwt = createJwt(claims);

    // When
    String result = JwtUtil.extractClaimValueAsString(jwt, "user.id");

    // Then
    assertThat(result).isEqualTo("12345");
  }

  @Test
  void extractClaimValueAsString_deeplyNestedClaim_returnsString() {
    // Given
    Map<String, Object> contact = Map.of("email", "user@example.com");
    Map<String, Object> profile = Map.of("contact", contact);
    Map<String, Object> user = Map.of("profile", profile);
    Map<String, Object> claims = Map.of("user", user);
    Jwt jwt = createJwt(claims);

    // When
    String result = JwtUtil.extractClaimValueAsString(jwt, "user.profile.contact.email");

    // Then
    assertThat(result).isEqualTo("user@example.com");
  }

  @Test
  void extractClaimValueAsString_missingClaim_returnsNull() {
    // Given
    Map<String, Object> claims = Collections.emptyMap();
    Jwt jwt = createJwt(claims);

    // When
    String result = JwtUtil.extractClaimValueAsString(jwt, "nonexistent");

    // Then
    assertThat(result).isNull();
  }

  @Test
  void extractClaimValueAsString_missingNestedClaim_returnsNull() {
    // Given
    Map<String, Object> claims = Map.of("realm_access", Map.of("other", "value"));
    Jwt jwt = createJwt(claims);

    // When
    String result = JwtUtil.extractClaimValueAsString(jwt, "realm_access.roles");

    // Then
    assertThat(result).isNull();
  }

  @Test
  void extractClaimValueAsString_nullClaimValue_returnsNull() {
    // Given
    Map<String, Object> claims = new HashMap<>();
    claims.put("email", null);
    Jwt jwt = createJwt(claims);

    // When
    String result = JwtUtil.extractClaimValueAsString(jwt, "email");

    // Then
    assertThat(result).isNull();
  }

  @Test
  void extractClaimValueAsString_nestedNullClaimValue_returnsNull() {
    // Given
    Map<String, Object> user = new HashMap<>();
    user.put("email", null);
    Map<String, Object> claims = Map.of("user", user);
    Jwt jwt = createJwt(claims);

    // When
    String result = JwtUtil.extractClaimValueAsString(jwt, "user.email");

    // Then
    assertThat(result).isNull();
  }

  @Test
  void extractClaimValueAsString_nestedClaimWithNullIntermediate_returnsNull() {
    // Given
    Map<String, Object> level1 = new HashMap<>();
    level1.put("level2", null);
    Map<String, Object> claims = Map.of("level1", level1);
    Jwt jwt = createJwt(claims);

    // When
    String result = JwtUtil.extractClaimValueAsString(jwt, "level1.level2.level3");

    // Then
    assertThat(result).isNull();
  }

  @Test
  void extractClaimValueAsString_nestedClaimWithNonMapIntermediate_returnsNull() {
    // Given
    Map<String, Object> claims = Map.of("level1", "not-a-map");
    Jwt jwt = createJwt(claims);

    // When
    String result = JwtUtil.extractClaimValueAsString(jwt, "level1.level2");

    // Then
    assertThat(result).isNull();
  }

  @Test
  void extractClaimValueAsString_nestedClaimWithCollectionIntermediate_returnsNull() {
    // Given
    Map<String, Object> claims = Map.of("level1", Arrays.asList("item1", "item2"));
    Jwt jwt = createJwt(claims);

    // When
    String result = JwtUtil.extractClaimValueAsString(jwt, "level1.level2");

    // Then
    assertThat(result).isNull();
  }

  @Test
  void extractClaimValueAsString_nestedClaimWithStringIntermediate_returnsNull() {
    // Given
    Map<String, Object> claims = Map.of("level1", "string-value");
    Jwt jwt = createJwt(claims);

    // When
    String result = JwtUtil.extractClaimValueAsString(jwt, "level1.level2");

    // Then
    assertThat(result).isNull();
  }

  @Test
  void extractClaimValueAsString_nestedClaimWithNullDuringLoop_returnsNull() {
    // Given - Create a nested structure where intermediate becomes null
    Map<String, Object> level2 = new HashMap<>();
    level2.put("level3", null);
    Map<String, Object> level1 = Map.of("level2", level2);
    Map<String, Object> claims = Map.of("level1", level1);
    Jwt jwt = createJwt(claims);

    // When - Navigate through level1.level2.level3.level4 where level3 is null
    // This tests the `current != null` branch in the loop condition
    String result = JwtUtil.extractClaimValueAsString(jwt, "level1.level2.level3.level4");

    // Then
    assertThat(result).isNull();
  }

  @Test
  void extractClaimValueAsString_nestedClaimWithNullInMiddle_returnsNull() {
    // Given
    Map<String, Object> level1 = new HashMap<>();
    level1.put("level2", null);
    Map<String, Object> claims = Map.of("level1", level1);
    Jwt jwt = createJwt(claims);

    // When - This tests the loop exit when current becomes null
    String result = JwtUtil.extractClaimValueAsString(jwt, "level1.level2.level3");

    // Then
    assertThat(result).isNull();
  }

  @Test
  void extractClaimValueAsString_claimWithNullAfterNavigation_handlesGracefully() {
    // Given
    Map<String, Object> level2 = new HashMap<>();
    level2.put("level3", null);
    Map<String, Object> level1 = Map.of("level2", level2);
    Map<String, Object> claims = Map.of("level1", level1);
    Jwt jwt = createJwt(claims);

    // When
    String result = JwtUtil.extractClaimValueAsString(jwt, "level1.level2.level3");

    // Then
    assertThat(result).isNull();
  }

  @Test
  void extractClaimValueAsString_loopExitsWhenCurrentBecomesNull_returnsNull() {
    // Given - Create a nested structure where an intermediate map contains null
    // This tests the `current != null` branch in the loop condition
    Map<String, Object> level2 = new HashMap<>();
    level2.put("level3", null);  // This will make current null during loop iteration
    Map<String, Object> level1 = Map.of("level2", level2);
    Map<String, Object> claims = Map.of("level1", level1);
    Jwt jwt = createJwt(claims);

    // When - Navigate through level1.level2.level3.level4
    // The loop should exit when current becomes null at level3
    String result = JwtUtil.extractClaimValueAsString(jwt, "level1.level2.level3.level4");

    // Then
    assertThat(result).isNull();
  }

  @Test
  void extractNestedClaimValuesAsList_nullAtFirstLevel_returnsEmptyList() {
    // Given - Test when the first claim part is null (before loop)
    Map<String, Object> claims = new HashMap<>();
    claims.put("first", null);
    Jwt jwt = createJwt(claims);

    // When - Try to navigate deeper from a null value
    List<String> result = JwtUtil.extractNestedClaimValuesAsList(jwt, "first.second");

    // Then
    assertThat(result).isEmpty();
  }

  @Test
  void extractNestedClaimValuesAsList_mapReturnsNullDuringNavigation_returnsEmptyList() {
    // Given - Map that returns null for a key
    Map<String, Object> level1 = new HashMap<>();
    level1.put("level2", null);  // Map.get() returns null
    Map<String, Object> claims = Map.of("level1", level1);
    Jwt jwt = createJwt(claims);

    // When - Navigate through level1.level2.level3
    // After getting level2 (which is null), the loop continues but deepClaim is null
    List<String> result = JwtUtil.extractNestedClaimValuesAsList(jwt, "level1.level2.level3");

    // Then
    assertThat(result).isEmpty();
  }

  @Test
  void extractClaimValueAsString_mapReturnsNullDuringLoop_returnsNull() {
    // Given - Map that returns null for a key during navigation
    Map<String, Object> level1 = new HashMap<>();
    level1.put("level2", null);
    Map<String, Object> claims = Map.of("level1", level1);
    Jwt jwt = createJwt(claims);

    // When - Navigate through level1.level2.level3
    // The loop should exit when current becomes null
    String result = JwtUtil.extractClaimValueAsString(jwt, "level1.level2.level3");

    // Then
    assertThat(result).isNull();
  }

  @Test
  void extractNestedClaimValuesAsList_multipleLevelsWithNullInBetween_returnsEmptyList() {
    // Given - Multiple levels where one intermediate is null
    Map<String, Object> level3 = new HashMap<>();
    level3.put("level4", null);
    Map<String, Object> level2 = new HashMap<>();
    level2.put("level3", level3);
    Map<String, Object> level1 = Map.of("level2", level2);
    Map<String, Object> claims = Map.of("level1", level1);
    Jwt jwt = createJwt(claims);

    // When
    List<String> result = JwtUtil.extractNestedClaimValuesAsList(jwt, "level1.level2.level3.level4.level5");

    // Then
    assertThat(result).isEmpty();
  }

  @Test
  void extractClaimValueAsString_multipleLevelsWithNullInBetween_returnsNull() {
    // Given - Multiple levels where one intermediate is null
    Map<String, Object> level3 = new HashMap<>();
    level3.put("level4", null);
    Map<String, Object> level2 = new HashMap<>();
    level2.put("level3", level3);
    Map<String, Object> level1 = Map.of("level2", level2);
    Map<String, Object> claims = Map.of("level1", level1);
    Jwt jwt = createJwt(claims);

    // When
    String result = JwtUtil.extractClaimValueAsString(jwt, "level1.level2.level3.level4.level5");

    // Then
    assertThat(result).isNull();
  }

  @Test
  void extractNestedClaimValuesAsList_integerDuringNavigation_returnsEmptyList() {
    // Given
    Map<String, Object> claims = Map.of("level1", 12345);
    Jwt jwt = createJwt(claims);

    // When
    List<String> result = JwtUtil.extractNestedClaimValuesAsList(jwt, "level1.level2");

    // Then
    assertThat(result).isEmpty();
  }

  @Test
  void extractClaimValueAsString_integerDuringNavigation_returnsNull() {
    // Given
    Map<String, Object> claims = Map.of("level1", 12345);
    Jwt jwt = createJwt(claims);

    // When
    String result = JwtUtil.extractClaimValueAsString(jwt, "level1.level2");

    // Then
    assertThat(result).isNull();
  }

  @Test
  void extractNestedClaimValuesAsList_booleanDuringNavigation_returnsEmptyList() {
    // Given
    Map<String, Object> claims = Map.of("level1", true);
    Jwt jwt = createJwt(claims);

    // When
    List<String> result = JwtUtil.extractNestedClaimValuesAsList(jwt, "level1.level2");

    // Then
    assertThat(result).isEmpty();
  }

  @Test
  void extractClaimValueAsString_booleanDuringNavigation_returnsNull() {
    // Given
    Map<String, Object> claims = Map.of("level1", true);
    Jwt jwt = createJwt(claims);

    // When
    String result = JwtUtil.extractClaimValueAsString(jwt, "level1.level2");

    // Then
    assertThat(result).isNull();
  }

  @Test
  void extractNestedClaimValuesAsList_nestedMapWithNullKey_returnsEmptyList() {
    // Given - Map that has a null key (edge case)
    Map<String, Object> level1 = new HashMap<>();
    level1.put(null, "value");  // null key
    Map<String, Object> claims = Map.of("level1", level1);
    Jwt jwt = createJwt(claims);

    // When - Try to access a non-null key that doesn't exist
    List<String> result = JwtUtil.extractNestedClaimValuesAsList(jwt, "level1.nonexistent");

    // Then
    assertThat(result).isEmpty();
  }

  @Test
  void extractClaimValueAsString_nestedMapWithNullKey_returnsNull() {
    // Given - Map that has a null key (edge case)
    Map<String, Object> level1 = new HashMap<>();
    level1.put(null, "value");  // null key
    Map<String, Object> claims = Map.of("level1", level1);
    Jwt jwt = createJwt(claims);

    // When - Try to access a non-null key that doesn't exist
    String result = JwtUtil.extractClaimValueAsString(jwt, "level1.nonexistent");

    // Then
    assertThat(result).isNull();
  }

  @Test
  void extractNestedClaimValuesAsList_finalValueIsBoolean_returnsEmptyList() {
    // Given
    Map<String, Object> claims = Map.of("flag", true);
    Jwt jwt = createJwt(claims);

    // When
    List<String> result = JwtUtil.extractNestedClaimValuesAsList(jwt, "flag");

    // Then
    assertThat(result).isEmpty();
  }

  @Test
  void extractNestedClaimValuesAsList_finalValueIsLong_returnsEmptyList() {
    // Given
    Map<String, Object> claims = Map.of("id", 999L);
    Jwt jwt = createJwt(claims);

    // When
    List<String> result = JwtUtil.extractNestedClaimValuesAsList(jwt, "id");

    // Then
    assertThat(result).isEmpty();
  }

  @Test
  void extractNestedClaimValuesAsList_finalValueIsDouble_returnsEmptyList() {
    // Given
    Map<String, Object> claims = Map.of("price", 99.99);
    Jwt jwt = createJwt(claims);

    // When
    List<String> result = JwtUtil.extractNestedClaimValuesAsList(jwt, "price");

    // Then
    assertThat(result).isEmpty();
  }

  @Test
  void extractNestedClaimValuesAsList_finalValueIsMap_returnsEmptyList() {
    // Given
    Map<String, Object> nested = Map.of("key", "value");
    Map<String, Object> claims = Map.of("nested", nested);
    Jwt jwt = createJwt(claims);

    // When
    List<String> result = JwtUtil.extractNestedClaimValuesAsList(jwt, "nested");

    // Then
    assertThat(result).isEmpty();
  }

  @Test
  void extractClaimValueAsString_finalValueIsMap_throwsIllegalStateException() {
    // Given
    Map<String, Object> nested = Map.of("key", "value");
    Map<String, Object> claims = Map.of("nested", nested);
    Jwt jwt = createJwt(claims);

    // When/Then - Should throw IllegalStateException
    assertThatThrownBy(() -> JwtUtil.extractClaimValueAsString(jwt, "nested"))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("resolved to a Map");
  }

  @Test
  void extractClaimValueAsString_finalValueIsList_throwsIllegalStateException() {
    // Given
    Map<String, Object> claims = Map.of("items", Arrays.asList("a", "b", "c"));
    Jwt jwt = createJwt(claims);

    // When/Then - Should throw IllegalStateException
    assertThatThrownBy(() -> JwtUtil.extractClaimValueAsString(jwt, "items"))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("resolved to a collection");
  }

  @Test
  void extractClaimValueAsString_finalValueIsArray_throwsIllegalStateException() {
    // Given
    Map<String, Object> claims = Map.of("array", new int[]{1, 2, 3});
    Jwt jwt = createJwt(claims);

    // When/Then - Should throw IllegalStateException
    assertThatThrownBy(() -> JwtUtil.extractClaimValueAsString(jwt, "array"))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("resolved to an array");
  }

  @Test
  void extractClaimValueAsString_nestedClaimWithList_throwsIllegalStateException() {
    // Given
    Map<String, Object> level1 = Map.of("items", Arrays.asList("a", "b"));
    Map<String, Object> claims = Map.of("level1", level1);
    Jwt jwt = createJwt(claims);

    // When/Then - Should throw IllegalStateException
    assertThatThrownBy(() -> JwtUtil.extractClaimValueAsString(jwt, "level1.items"))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("resolved to a collection");
  }

  @Test
  void extractClaimValueAsString_nestedClaimWithArray_throwsIllegalStateException() {
    // Given
    Map<String, Object> level1 = Map.of("array", new String[]{"a", "b"});
    Map<String, Object> claims = Map.of("level1", level1);
    Jwt jwt = createJwt(claims);

    // When/Then - Should throw IllegalStateException
    assertThatThrownBy(() -> JwtUtil.extractClaimValueAsString(jwt, "level1.array"))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("resolved to an array");
  }

  @Test
  void extractClaimValueAsString_nestedClaimWithMap_throwsIllegalStateException() {
    // Given
    Map<String, Object> nested = Map.of("key", "value");
    Map<String, Object> level1 = Map.of("nested", nested);
    Map<String, Object> claims = Map.of("level1", level1);
    Jwt jwt = createJwt(claims);

    // When/Then - Should throw IllegalStateException
    assertThatThrownBy(() -> JwtUtil.extractClaimValueAsString(jwt, "level1.nested"))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("resolved to a Map");
  }

  @Test
  void extractNestedClaimValuesAsList_nestedMapWithIntegerIntermediate_returnsEmptyList() {
    // Given
    Map<String, Object> claims = Map.of("level1", 123);
    Jwt jwt = createJwt(claims);

    // When
    List<String> result = JwtUtil.extractNestedClaimValuesAsList(jwt, "level1.level2");

    // Then
    assertThat(result).isEmpty();
  }

  @Test
  void extractClaimValueAsString_nestedMapWithIntegerIntermediate_returnsNull() {
    // Given
    Map<String, Object> claims = Map.of("level1", 123);
    Jwt jwt = createJwt(claims);

    // When
    String result = JwtUtil.extractClaimValueAsString(jwt, "level1.level2");

    // Then
    assertThat(result).isNull();
  }

  @Test
  void extractClaimValueAsString_primitiveArray_throwsIllegalStateException() {
    // Given - Test primitive array types
    Map<String, Object> claims1 = Map.of("intArray", new int[]{1, 2, 3});
    Map<String, Object> claims2 = Map.of("longArray", new long[]{1L, 2L, 3L});
    Map<String, Object> claims3 = Map.of("stringArray", new String[]{"a", "b"});
    Jwt jwt1 = createJwt(claims1);
    Jwt jwt2 = createJwt(claims2);
    Jwt jwt3 = createJwt(claims3);

    // When/Then - Should throw IllegalStateException for all array types
    assertThatThrownBy(() -> JwtUtil.extractClaimValueAsString(jwt1, "intArray"))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("resolved to an array");
    
    assertThatThrownBy(() -> JwtUtil.extractClaimValueAsString(jwt2, "longArray"))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("resolved to an array");
    
    assertThatThrownBy(() -> JwtUtil.extractClaimValueAsString(jwt3, "stringArray"))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("resolved to an array");
  }

  @Test
  void extractClaimValueAsString_nestedPrimitiveArray_throwsIllegalStateException() {
    // Given
    Map<String, Object> level1 = Map.of("array", new boolean[]{true, false});
    Map<String, Object> claims = Map.of("level1", level1);
    Jwt jwt = createJwt(claims);

    // When/Then
    assertThatThrownBy(() -> JwtUtil.extractClaimValueAsString(jwt, "level1.array"))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("resolved to an array");
  }

  @Test
  void extractClaimValueAsString_differentCollectionTypes_throwsIllegalStateException() {
    // Given - Test different Collection implementations
    Map<String, Object> claims1 = Map.of("list", Arrays.asList("a", "b"));
    Map<String, Object> claims2 = Map.of("set", java.util.Set.of("a", "b"));
    Jwt jwt1 = createJwt(claims1);
    Jwt jwt2 = createJwt(claims2);

    // When/Then
    assertThatThrownBy(() -> JwtUtil.extractClaimValueAsString(jwt1, "list"))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("resolved to a collection");
    
    assertThatThrownBy(() -> JwtUtil.extractClaimValueAsString(jwt2, "set"))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("resolved to a collection");
  }

  @Test
  void extractClaimValueAsString_nestedDifferentCollectionTypes_throwsIllegalStateException() {
    // Given
    Map<String, Object> level1 = Map.of("set", java.util.Set.of("a", "b"));
    Map<String, Object> claims = Map.of("level1", level1);
    Jwt jwt = createJwt(claims);

    // When/Then
    assertThatThrownBy(() -> JwtUtil.extractClaimValueAsString(jwt, "level1.set"))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("resolved to a collection");
  }

  @Test
  void extractNestedClaimValuesAsList_differentCollectionTypes_returnsList() {
    // Given - Test different Collection implementations
    Map<String, Object> claims1 = Map.of("list", Arrays.asList("a", "b", "c"));
    Map<String, Object> claims2 = Map.of("set", java.util.Set.of("x", "y", "z"));
    Jwt jwt1 = createJwt(claims1);
    Jwt jwt2 = createJwt(claims2);

    // When
    List<String> result1 = JwtUtil.extractNestedClaimValuesAsList(jwt1, "list");
    List<String> result2 = JwtUtil.extractNestedClaimValuesAsList(jwt2, "set");

    // Then
    assertThat(result1).containsExactlyInAnyOrder("a", "b", "c");
    assertThat(result2).containsExactlyInAnyOrder("x", "y", "z");
  }

  @Test
  void extractNestedClaimValuesAsList_nestedDifferentCollectionTypes_returnsList() {
    // Given
    Map<String, Object> level1 = Map.of("set", java.util.Set.of("a", "b"));
    Map<String, Object> claims = Map.of("level1", level1);
    Jwt jwt = createJwt(claims);

    // When
    List<String> result = JwtUtil.extractNestedClaimValuesAsList(jwt, "level1.set");

    // Then
    assertThat(result).containsExactlyInAnyOrder("a", "b");
  }

  @Test
  void extractClaimValueAsString_booleanValue_returnsString() {
    // Given
    Map<String, Object> claims = Map.of("flag", true, "enabled", false);
    Jwt jwt = createJwt(claims);

    // When
    String result1 = JwtUtil.extractClaimValueAsString(jwt, "flag");
    String result2 = JwtUtil.extractClaimValueAsString(jwt, "enabled");

    // Then
    assertThat(result1).isEqualTo("true");
    assertThat(result2).isEqualTo("false");
  }

  @Test
  void extractClaimValueAsString_numberValues_returnsString() {
    // Given
    Map<String, Object> claims = Map.of(
        "intVal", 42,
        "longVal", 999L,
        "doubleVal", 3.14,
        "floatVal", 2.5f
    );
    Jwt jwt = createJwt(claims);

    // When
    String intResult = JwtUtil.extractClaimValueAsString(jwt, "intVal");
    String longResult = JwtUtil.extractClaimValueAsString(jwt, "longVal");
    String doubleResult = JwtUtil.extractClaimValueAsString(jwt, "doubleVal");
    String floatResult = JwtUtil.extractClaimValueAsString(jwt, "floatVal");

    // Then
    assertThat(intResult).isEqualTo("42");
    assertThat(longResult).isEqualTo("999");
    assertThat(doubleResult).isEqualTo("3.14");
    assertThat(floatResult).isEqualTo("2.5");
  }

  @Test
  void extractClaimValueAsString_nestedNumberValue_returnsString() {
    // Given
    Map<String, Object> user = Map.of("id", 12345);
    Map<String, Object> claims = Map.of("user", user);
    Jwt jwt = createJwt(claims);

    // When
    String result = JwtUtil.extractClaimValueAsString(jwt, "user.id");

    // Then
    assertThat(result).isEqualTo("12345");
  }

  private Jwt createJwt(Map<String, Object> claims) {
    return Jwt.withTokenValue("test-token")
        .header("alg", "RS256")
        .claim("sub", "test-subject")
        .claims(c -> c.putAll(claims))
        .issuedAt(Instant.now())
        .expiresAt(Instant.now().plusSeconds(3600))
        .build();
  }
}
