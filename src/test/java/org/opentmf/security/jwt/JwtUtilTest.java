package org.opentmf.security.jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Tests for {@link JwtUtil}.
 */
class JwtUtilTest {

  // ===================== extractNestedClaimValuesAsList =====================

  @Test
  void extractList_nullJwt_returnsEmptyList() {
    assertThat(JwtUtil.extractNestedClaimValuesAsList(null, "email")).isEmpty();
  }

  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(strings = {"   "})
  void extractList_blankClaimName_returnsEmptyList(String claimName) {
    Jwt jwt = jwt(Map.of("email", "user@example.com"));

    assertThat(JwtUtil.extractNestedClaimValuesAsList(jwt, claimName)).isEmpty();
  }

  @ParameterizedTest
  @MethodSource("singleStringClaims")
  void extractList_stringClaim_returnsSingletonList(
      Map<String, Object> claims, String claimName, String expected) {
    Jwt jwt = jwt(claims);

    assertThat(JwtUtil.extractNestedClaimValuesAsList(jwt, claimName)).containsExactly(expected);
  }

  static Stream<Arguments> singleStringClaims() {
    return Stream.of(
        arguments(Map.of("email", "user@example.com"), "email", "user@example.com"),
        arguments(Map.of("user", Map.of("email", "user@example.com")), "user.email",
            "user@example.com"),
        arguments(Map.of("level1", Map.of("level2", "value")), "level1.level2", "value"),
        arguments(Map.of("level1", Map.of("level2", Map.of("level3", "value"))),
            "level1.level2.level3", "value"));
  }

  @ParameterizedTest
  @MethodSource("collectionClaims")
  void extractList_collectionClaim_returnsStringifiedNonNullElements(
      Map<String, Object> claims, String claimName, List<String> expected) {
    Jwt jwt = jwt(claims);

    assertThat(JwtUtil.extractNestedClaimValuesAsList(jwt, claimName))
        .containsExactlyElementsOf(expected);
  }

  static Stream<Arguments> collectionClaims() {
    return Stream.of(
        arguments(Map.of("roles", List.of("admin", "user", "guest")), "roles",
            List.of("admin", "user", "guest")),
        arguments(Map.of("realm_access", Map.of("roles", List.of("admin", "user"))),
            "realm_access.roles", List.of("admin", "user")),
        arguments(
            Map.of("realm", Map.of("access", Map.of("roles",
                Map.of("values", List.of("admin", "user"))))),
            "realm.access.roles.values", List.of("admin", "user")),
        arguments(Map.of("mixed", List.of(123, "text", true, 456L)), "mixed",
            List.of("123", "text", "true", "456")),
        arguments(Map.of("roles", Arrays.asList("admin", null, "user", null, "guest")), "roles",
            List.of("admin", "user", "guest")),
        arguments(Map.of("realm_access", Map.of("roles", Arrays.asList("admin", null, "user"))),
            "realm_access.roles", List.of("admin", "user")));
  }

  @Test
  void extractList_setClaims_returnsAllElements() {
    Jwt topLevel = jwt(Map.of("set", Set.of("x", "y", "z")));
    Jwt nested = jwt(Map.of("level1", Map.of("set", Set.of("a", "b"))));

    assertThat(JwtUtil.extractNestedClaimValuesAsList(topLevel, "set"))
        .containsExactlyInAnyOrder("x", "y", "z");
    assertThat(JwtUtil.extractNestedClaimValuesAsList(nested, "level1.set"))
        .containsExactlyInAnyOrder("a", "b");
  }

  @ParameterizedTest
  @MethodSource("emptyListScenarios")
  void extractList_unresolvableOrNonListClaim_returnsEmptyList(
      Map<String, Object> claims, String claimName) {
    Jwt jwt = jwt(claims);

    assertThat(JwtUtil.extractNestedClaimValuesAsList(jwt, claimName)).isEmpty();
  }

  static Stream<Arguments> emptyListScenarios() {
    return Stream.of(
        // missing claims
        arguments(Map.of(), "nonexistent"),
        arguments(Map.of("realm_access", Map.of("other", "value")), "realm_access.roles"),
        arguments(Map.of("level1", mapOf(null, "value")), "level1.nonexistent"),
        // null values, at the end and during navigation
        arguments(Map.of("realm_access", mapOf("roles", null)), "realm_access.roles"),
        arguments(mapOf("first", null), "first.second"),
        arguments(Map.of("level1", mapOf("level2", null)), "level1.level2.level3"),
        arguments(Map.of("level1", Map.of("level2", Map.of("level3", mapOf("level4", null)))),
            "level1.level2.level3.level4.level5"),
        // non-map intermediates
        arguments(Map.of("realm_access", "not-a-map"), "realm_access.roles"),
        arguments(Map.of("level1", List.of("item1", "item2")), "level1.level2"),
        arguments(Map.of("level1", 12345), "level1.level2"),
        arguments(Map.of("level1", true), "level1.level2"),
        // empty or all-null collections
        arguments(Map.of("roles", List.of()), "roles"),
        arguments(Map.of("realm_access", Map.of("roles", List.of())), "realm_access.roles"),
        arguments(Map.of("roles", Arrays.asList(null, null)), "roles"),
        // final value neither String nor Collection
        arguments(Map.of("number", 12345), "number"),
        arguments(Map.of("flag", true), "flag"),
        arguments(Map.of("id", 999L), "id"),
        arguments(Map.of("price", 99.99), "price"),
        arguments(Map.of("nested", Map.of("key", "value")), "nested"),
        // degenerate claim names: blank first part or empty middle part
        arguments(Map.of("email", "user@example.com"), ".email"),
        arguments(Map.of("email", "user@example.com"), "  .email"),
        arguments(Map.of("email", "user@example.com"), "\t.email"),
        arguments(Map.of("level1", Map.of("level3", Map.of("value", "result"))),
            "level1..level3"));
  }

  // ======================== extractClaimValueAsString ========================

  @Test
  void extractString_nullJwt_returnsNull() {
    assertThat(JwtUtil.extractClaimValueAsString(null, "email")).isNull();
  }

  @ParameterizedTest
  @NullAndEmptySource
  void extractString_nullOrEmptyClaimName_returnsNull(String claimName) {
    Jwt jwt = jwt(Map.of("email", "user@example.com"));

    assertThat(JwtUtil.extractClaimValueAsString(jwt, claimName)).isNull();
  }

  @ParameterizedTest
  @MethodSource("scalarClaims")
  void extractString_scalarClaim_returnsStringValue(
      Map<String, Object> claims, String claimName, String expected) {
    Jwt jwt = jwt(claims);

    assertThat(JwtUtil.extractClaimValueAsString(jwt, claimName)).isEqualTo(expected);
  }

  static Stream<Arguments> scalarClaims() {
    return Stream.of(
        arguments(Map.of("email", "user@example.com"), "email", "user@example.com"),
        arguments(Map.of("number", 12345), "number", "12345"),
        arguments(Map.of("boolean", true), "boolean", "true"),
        arguments(Map.of("enabled", false), "enabled", "false"),
        arguments(Map.of("long", 999L), "long", "999"),
        arguments(Map.of("double", 3.14), "double", "3.14"),
        arguments(Map.of("float", 2.5f), "float", "2.5"),
        arguments(Map.of("user", Map.of("email", "user@example.com")), "user.email",
            "user@example.com"),
        arguments(Map.of("user", Map.of("id", 12345)), "user.id", "12345"),
        arguments(
            Map.of("user", Map.of("profile", Map.of("contact",
                Map.of("email", "user@example.com")))),
            "user.profile.contact.email", "user@example.com"));
  }

  @ParameterizedTest
  @MethodSource("nullResultScenarios")
  void extractString_unresolvableClaim_returnsNull(Map<String, Object> claims, String claimName) {
    Jwt jwt = jwt(claims);

    assertThat(JwtUtil.extractClaimValueAsString(jwt, claimName)).isNull();
  }

  static Stream<Arguments> nullResultScenarios() {
    return Stream.of(
        // missing claims
        arguments(Map.of(), "nonexistent"),
        arguments(Map.of("realm_access", Map.of("other", "value")), "realm_access.roles"),
        arguments(Map.of("email", "user@example.com"), "   "),
        arguments(Map.of("level1", mapOf(null, "value")), "level1.nonexistent"),
        // null values, at the end and during navigation
        arguments(mapOf("email", null), "email"),
        arguments(Map.of("user", mapOf("email", null)), "user.email"),
        arguments(Map.of("level1", mapOf("level2", null)), "level1.level2.level3"),
        arguments(Map.of("level1", Map.of("level2", mapOf("level3", null))),
            "level1.level2.level3.level4"),
        arguments(Map.of("level1", Map.of("level2", Map.of("level3", mapOf("level4", null)))),
            "level1.level2.level3.level4.level5"),
        // non-map intermediates
        arguments(Map.of("level1", "not-a-map"), "level1.level2"),
        arguments(Map.of("level1", 123), "level1.level2"),
        arguments(Map.of("level1", true), "level1.level2"),
        arguments(Map.of("level1", List.of("a", "b")), "level1.level2"),
        // degenerate claim names
        arguments(Map.of("email", "user@example.com"), ".email"),
        arguments(Map.of("email", "user@example.com"), "  .email"),
        arguments(Map.of("email", "user@example.com"), "\t.email"),
        arguments(Map.of("email", "user@example.com"), "..."),
        arguments(Map.of("email", "user@example.com"), ".."),
        arguments(Map.of("level1", Map.of("level2", "value")), "level1..level2"),
        arguments(Map.of("level1", Map.of("level2", Map.of("level3", "value"))),
            "level1..level2.level3"));
  }

  @ParameterizedTest
  @MethodSource("nonScalarScenarios")
  void extractString_nonScalarClaim_throwsIllegalStateException(
      Map<String, Object> claims, String claimName, String expectedMessagePart) {
    Jwt jwt = jwt(claims);

    assertThatThrownBy(() -> JwtUtil.extractClaimValueAsString(jwt, claimName))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining(expectedMessagePart);
  }

  static Stream<Arguments> nonScalarScenarios() {
    return Stream.of(
        arguments(Map.of("nested", Map.of("key", "value")), "nested", "resolved to a Map"),
        arguments(Map.of("level1", Map.of("nested", Map.of("key", "value"))), "level1.nested",
            "resolved to a Map"),
        arguments(Map.of("items", List.of("a", "b", "c")), "items", "resolved to a collection"),
        arguments(Map.of("set", Set.of("a", "b")), "set", "resolved to a collection"),
        arguments(Map.of("level1", Map.of("items", List.of("a", "b"))), "level1.items",
            "resolved to a collection"),
        arguments(Map.of("level1", Map.of("set", Set.of("a", "b"))), "level1.set",
            "resolved to a collection"),
        arguments(Map.of("intArray", new int[] {1, 2, 3}), "intArray", "resolved to an array"),
        arguments(Map.of("longArray", new long[] {1L, 2L}), "longArray", "resolved to an array"),
        arguments(Map.of("stringArray", new String[] {"a", "b"}), "stringArray",
            "resolved to an array"),
        arguments(Map.of("level1", Map.of("array", new boolean[] {true, false})), "level1.array",
            "resolved to an array"),
        arguments(Map.of("level1", Map.of("array", new String[] {"a", "b"})), "level1.array",
            "resolved to an array"));
  }

  // ================================ fixtures ================================

  private static Jwt jwt(Map<String, Object> claims) {
    return Jwt.withTokenValue("test-token")
        .header("alg", "RS256")
        .claim("sub", "test-subject")
        .claims(c -> c.putAll(claims))
        .issuedAt(Instant.now())
        .expiresAt(Instant.now().plusSeconds(3600))
        .build();
  }

  /** {@link Map#of} rejects null keys/values, which several scenarios need. */
  private static Map<String, Object> mapOf(String key, Object value) {
    Map<String, Object> map = new HashMap<>();
    map.put(key, value);
    return map;
  }
}
