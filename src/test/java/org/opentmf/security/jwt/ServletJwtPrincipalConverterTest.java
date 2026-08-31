package org.opentmf.security.jwt;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.StringUtils;

class ServletJwtPrincipalConverterTest {
  /** Fixed, so the fixtures are deterministic — nothing here validates real expiry. */
  private static final Instant FIXED_NOW = Instant.parse("2026-01-01T12:00:00Z");

  private GrantedAuthoritiesConverter authoritiesConverter;
  private ServletJwtPrincipalConverter converter;

  @BeforeEach
  void setUp() {
    authoritiesConverter = new GrantedAuthoritiesConverter("groups");
  }

  @Test
  void testConvert_withPrimaryClaim_returnsPrimaryValue() {
    // Given
    String primaryClaim = "email";
    List<String> fallbackClaims = List.of("client_id", "azp");
    converter = new ServletJwtPrincipalConverter(
        primaryClaim, fallbackClaims, authoritiesConverter);

    Jwt jwt = createJwt(Map.of(
        "email", "user@example.com",
        "sub", "user-123",
        "groups", List.of("read", "write")
    ));

    // When
    var result = converter.convert(jwt);

    // Then
    assertNotNull(result);
    assertEquals("user@example.com", result.getName());
    assertTrue(result.getAuthorities().stream()
        .map(GrantedAuthority::getAuthority)
        .anyMatch(a -> a.equals("read")));
  }

  @Test
  void testConvert_withPrimaryClaimMissing_usesFirstFallback() {
    // Given
    String primaryClaim = "email";
    List<String> fallbackClaims = List.of("client_id", "azp");
    converter = new ServletJwtPrincipalConverter(
        primaryClaim, fallbackClaims, authoritiesConverter);

    Jwt jwt = createJwt(Map.of(
        "client_id", "my-client-id",
        "sub", "user-123",
        "groups", List.of("read")
    ));

    // When
    var result = converter.convert(jwt);

    // Then
    assertNotNull(result);
    assertEquals("my-client-id", result.getName());
  }

  @Test
  void testConvert_withMultipleFallbacks_usesSecondFallback() {
    // Given
    String primaryClaim = "email";
    List<String> fallbackClaims = List.of("client_id", "azp", "appid");
    converter = new ServletJwtPrincipalConverter(
        primaryClaim, fallbackClaims, authoritiesConverter);

    Jwt jwt = createJwt(Map.of(
        "azp", "authorized-party",
        "sub", "user-123",
        "groups", List.of("read")
    ));

    // When
    var result = converter.convert(jwt);

    // Then
    assertNotNull(result);
    assertEquals("authorized-party", result.getName());
  }

  @Test
  void testConvert_withAllClaimsMissing_usesSubject() {
    // Given
    String primaryClaim = "email";
    List<String> fallbackClaims = List.of("client_id", "azp");
    converter = new ServletJwtPrincipalConverter(
        primaryClaim, fallbackClaims, authoritiesConverter);

    Jwt jwt = createJwt(Map.of(
        "sub", "user-123",
        "groups", List.of("read")
    ));

    // When
    var result = converter.convert(jwt);

    // Then
    assertNotNull(result);
    assertEquals("user-123", result.getName());
  }

  @Test
  void testConvert_withEmptyPrimaryClaim_usesFallback() {
    // Given
    String primaryClaim = "email";
    List<String> fallbackClaims = List.of("client_id");
    converter = new ServletJwtPrincipalConverter(
        primaryClaim, fallbackClaims, authoritiesConverter);

    Jwt jwt = createJwt(Map.of(
        "email", "",
        "client_id", "my-client",
        "sub", "user-123",
        "groups", List.of("read")
    ));

    // When
    var result = converter.convert(jwt);

    // Then
    assertNotNull(result);
    assertEquals("my-client", result.getName());
  }

  @Test
  void testConvert_withNullPrimaryClaim_usesFallback() {
    // Given
    String primaryClaim = "email";
    List<String> fallbackClaims = List.of("client_id");
    converter = new ServletJwtPrincipalConverter(
        primaryClaim, fallbackClaims, authoritiesConverter);

    Jwt jwt = createJwt(Map.of(
        "client_id", "my-client",
        "sub", "user-123",
        "groups", List.of("read")
    ));

    // When
    var result = converter.convert(jwt);

    // Then
    assertNotNull(result);
    assertEquals("my-client", result.getName());
  }

  @Test
  void testConvert_withNestedClaim() {
    // Given
    String primaryClaim = "user.email";
    List<String> fallbackClaims = Collections.emptyList();
    converter = new ServletJwtPrincipalConverter(
        primaryClaim, fallbackClaims, authoritiesConverter);

    Jwt jwt = createJwt(Map.of(
        "user", Map.of("email", "nested@example.com"),
        "sub", "user-123",
        "groups", List.of("read")
    ));

    // When
    var result = converter.convert(jwt);

    // Then
    assertNotNull(result);
    assertEquals("nested@example.com", result.getName());
  }

  @Test
  void testConvert_withNoAuthoritiesConverter_returnsEmptyAuthorities() {
    // Given
    String primaryClaim = "email";
    List<String> fallbackClaims = Collections.emptyList();
    converter = new ServletJwtPrincipalConverter(
        primaryClaim, fallbackClaims, null);

    Jwt jwt = createJwt(Map.of(
        "email", "user@example.com",
        "sub", "user-123"
    ));

    // When
    var result = converter.convert(jwt);

    // Then
    assertNotNull(result);
    assertEquals("user@example.com", result.getName());
    assertTrue(result.getAuthorities().isEmpty());
  }

  @Test
  void testConvert_withNonStringClaim_usesToString() {
    // Given
    String primaryClaim = "user_id";
    List<String> fallbackClaims = Collections.emptyList();
    converter = new ServletJwtPrincipalConverter(
        primaryClaim, fallbackClaims, authoritiesConverter);

    Jwt jwt = createJwt(Map.of(
        "user_id", 12345,
        "sub", "user-123",
        "groups", List.of("read")
    ));

    // When
    var result = converter.convert(jwt);

    // Then
    assertNotNull(result);
    assertEquals("12345", result.getName());
  }

  @Test
  void testConvert_withNoFallbackClaims_usesSubject() {
    // Given
    String primaryClaim = "email";
    List<String> fallbackClaims = Collections.emptyList();
    converter = new ServletJwtPrincipalConverter(
        primaryClaim, fallbackClaims, authoritiesConverter);

    Jwt jwt = createJwt(Map.of(
        "sub", "user-123",
        "groups", List.of("read")
    ));

    // When
    var result = converter.convert(jwt);

    // Then
    assertNotNull(result);
    assertEquals("user-123", result.getName());
  }

  @Test
  void testConvert_withAllMissing_returnsNullPrincipal() {
    // Given
    String primaryClaim = "email";
    List<String> fallbackClaims = List.of("client_id", "azp");
    converter = new ServletJwtPrincipalConverter(
        primaryClaim, fallbackClaims, authoritiesConverter);

    // JWT without sub claim (shouldn't happen in practice, but testing edge case)
    Jwt jwt = Jwt.withTokenValue("token")
        .header("alg", "RS256")
        .claim("groups", List.of("read"))
        .issuedAt(FIXED_NOW)
        .expiresAt(FIXED_NOW.plusSeconds(3600))
        .build();

    // When
    var result = converter.convert(jwt);

    // Then — the converter supplies no principal name; whether the token reports that as null
    // or as "" is the framework's business (Spring Security 7.1 normalizes it to empty), so
    // this asserts only what the library itself guarantees: no invented principal.
    assertNotNull(result);
    assertFalse(StringUtils.hasText(result.getName()));
  }

  private Jwt createJwt(Map<String, Object> claims) {
    Jwt.Builder builder = Jwt.withTokenValue("test-token")
        .header("alg", "RS256")
        .issuedAt(FIXED_NOW)
        .expiresAt(FIXED_NOW.plusSeconds(3600));

    // Add subject if not present
    if (!claims.containsKey("sub")) {
      builder.claim("sub", "default-subject");
    }

    // Add all claims
    claims.forEach(builder::claim);

    return builder.build();
  }
}
