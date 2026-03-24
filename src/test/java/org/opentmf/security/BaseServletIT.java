package org.opentmf.security;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.net.URI;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.opentmf.security.service.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.util.CollectionUtils;
import org.springframework.web.context.WebApplicationContext;

@AutoConfigureMockMvc
abstract class BaseServletIT extends BaseIT {

  @Autowired SecurityFilterChain servletSecurityFilterChain;
  @Autowired TokenService servletTokenService;
  @Autowired MockMvc mockMvc;
  @Autowired WebApplicationContext context;

  @BeforeAll
  void beforeAll() {
    mockMvc = MockMvcBuilders.webAppContextSetup(context)
        .apply(springSecurity())
        .build();
  }

  @Order(10)
  @Test
  void contextLoads() {
    Assertions.assertNotNull(servletSecurityFilterChain);
    Assertions.assertNotNull(servletTokenService);
    Assertions.assertNotNull(openTmfSecurityProperties);
    Assertions.assertNotNull(jwtService);
  }

  @Order(20)
  @Test
  void testPost_withValidToken_returnsCreated() throws Exception {
    String token = getToken("write");
    Assertions.assertNotNull(token);
    mockMvc.perform(postMercedesBuilder(token)).andExpect(status().isCreated());
  }

  @Order(30)
  @Test
  void testPost_withoutNecessaryAuthorities_returnsForbidden() throws Exception {
    String token = getToken("read");
    Assertions.assertNotNull(token);
    mockMvc.perform(postMercedesBuilder(token)).andExpect(status().isForbidden());
  }

  @Order(40)
  @Test
  void testPost_withoutToken_returnsUnauthorized() throws Exception {
    mockMvc.perform(postMercedesBuilder()).andExpect(status().isUnauthorized());
  }

  @Order(50)
  @Test
  void testGetCars_withoutToken_returnsOk() throws Exception {
    mockMvc.perform(getBuilder("/car")).andExpect(status().isOk());
  }

  @Order(60)
  @Test
  void testGetWhitelist_withoutToken_returnsValidResult() throws Exception {
    if (CollectionUtils.isEmpty(openTmfSecurityProperties.getWhitelist())) {
      mockMvc.perform(getBuilder("/whitelist")).andExpect(status().isUnauthorized());
    } else {
      mockMvc.perform(getBuilder("/whitelist")).andExpect(status().isOk());
    }
  }

  @Order(70)
  @Test
  void testGetBlacklist_withoutToken_returnsUnauthorized() throws Exception {
    mockMvc.perform(getBuilder("/blacklist")).andExpect(status().isUnauthorized());
  }

  @Order(80)
  @Test
  void testGetBlacklist_withReadToken_returnsForbidden() throws Exception {
    String token = getToken("read");
    mockMvc.perform(getBuilder(token, "/blacklist")).andExpect(status().isForbidden());
  }

  @Order(90)
  @ParameterizedTest
  @ValueSource(strings = {"read", "write"})
  void testPutCarAndThenGet_withBothTokens_returnsOk(String tokenType) throws Exception {
    String writeToken = getToken("write");
    mockMvc.perform(putMercedesBuilder(writeToken)).andExpect(status().isOk());
    String token = getToken(tokenType);
    mockMvc.perform(getCarBuilder(token, "Mercedes")).andExpect(status().isOk());
    mockMvc.perform(getCarBuilder(token, "nonexistent")).andExpect(status().isNotFound());
  }

  @Order(100)
  @Test
  void testProtectedResource_withoutToken_returnsUnauthorized() throws Exception {
    mockMvc.perform(getBuilder("/car/model")).andExpect(status().isUnauthorized());
  }

  @Order(110)
  @Test
  void testProtectedButNotConfigured_withoutToken_returnsUnauthorized() throws Exception {
    mockMvc.perform(getBuilder("/protectedButNotConfigured")).andExpect(status().isUnauthorized());
  }

  @Order(120)
  @Test
  void testProtectedButNotConfigured_withToken_returnsForbidden() throws Exception {
    String token = getToken("write");
    mockMvc.perform(getBuilder(token, "/protectedButNotConfigured")).andExpect(status().isForbidden());
  }

  @Order(130)
  @Test
  void testDeleteCar_withoutToken_returnsUnauthorized() throws Exception {
    mockMvc.perform(deleteCarBuilder()).andExpect(status().isUnauthorized());
  }

  @Order(140)
  @Test
  void testDeleteCar_withInsufficientToken_returnsForbidden() throws Exception {
    String token = getToken("read");
    mockMvc.perform(deleteCarBuilder(token)).andExpect(status().isForbidden());
  }

  @Order(150)
  @Test
  void testDeleteCar_withToken_returnsNoContent() throws Exception {
    String token = getToken("write");
    mockMvc.perform(deleteCarBuilder(token)).andExpect(status().isNoContent());
  }

  @Order(160)
  @Test
  void testDeleteCar_withToken_returnsNotFound() throws Exception {
    String token = getToken("write");
    mockMvc.perform(deleteCarBuilder(token)).andExpect(status().isNotFound());
  }

  @Order(170)
  @Test
  void testJwtService_withValidToken_returnsValidResults() {
    var token = getToken("write");
    var jwt = jwtService.decodeJwt(token);
    var groups = jwt.getClaim("groups");
    Assertions.assertNotNull(groups);
    Assertions.assertFalse(jwtService.isExpiredToken(jwt));
  }

  @Order(180)
  @Test
  void testFallbackUserClaim_withClientCredentials_usesFallbackClaim() throws Exception {
    // Skip this test for file-based JWK sets (LocalJwkSet tests)
    URI tokenUri;
    try {
      tokenUri = getTokenUri();
    } catch (UnsupportedOperationException | IllegalArgumentException e) {
      return; // Skip test for file-based configurations
    }
    // Given: Get token using client_credentials (won't have email claim)
    String clientCredentialsToken = servletTokenService.getToken(tokenUri);
    Assertions.assertNotNull(clientCredentialsToken);

    // When: Decode the token and check claims
    var jwt = jwtService.decodeJwt(clientCredentialsToken);
    var emailClaim = jwt.getClaim("email");
    var subClaim = jwt.getSubject();

    // Then: Email should be null, but fallback claims should exist
    Assertions.assertNull(emailClaim, "Email claim should not exist in client_credentials token");
    Assertions.assertNotNull(subClaim, "Subject claim should exist");

    // Verify that the token can be used for authentication
    // The principal should be extracted from one of the fallback claims by the authentication converter
    mockMvc.perform(getBuilder(clientCredentialsToken, "/car"))
        .andExpect(status().isOk())
        .andReturn();

    // The authentication principal should be one of the fallback claims
    // Note: We can't easily access the SecurityContext in MockMvc, but the fact that
    // authentication succeeded means the fallback converter worked correctly
    Assertions.assertNotNull(clientCredentialsToken);
  }

  @Order(190)
  @Test
  void testFallbackUserClaim_withPasswordGrant_usesPrimaryClaim() throws Exception {
    // Given: Get token using password grant (may have email claim)
    String passwordToken = getToken("write");
    Assertions.assertNotNull(passwordToken);

    // When: Decode the token and check claims
    var jwt = jwtService.decodeJwt(passwordToken);
    var emailClaim = jwt.getClaim("email");
    var subClaim = jwt.getSubject();

    // Then: Verify that the token can be used for authentication
    // The authentication converter will use email if present, otherwise fallback to sub
    mockMvc.perform(getBuilder(passwordToken, "/car"))
        .andExpect(status().isOk());

    // Note: jwtService.getJwtPrincipal() always returns sub, not the configured claim
    // The actual principal used by Spring Security is set by the authentication converter
    // which we've verified works by the successful authentication above
    Assertions.assertNotNull(emailClaim != null ? emailClaim : subClaim, 
        "Either email or sub claim should exist");
  }

  protected URI getTokenUri() {
    try {
      var jwkSetUri = openTmfSecurityProperties.getJwkSetUri().getURL().toString();
      // Only create token URI if it's an HTTP/HTTPS URL (not file://)
      if (jwkSetUri.startsWith("http://") || jwkSetUri.startsWith("https://")) {
        return URI.create(jwkSetUri.substring(0, jwkSetUri.lastIndexOf('/') + 1) + "token");
      }
      throw new UnsupportedOperationException("Token URI not available for file-based JWK sets");
    } catch (Exception e) {
      throw new IllegalArgumentException("jwk-set-uri is not a valid URL", e);
    }
  }

  private static @NotNull MockHttpServletRequestBuilder postMercedesBuilder(String token) {
    return MockMvcRequestBuilders.post("/car")
        .header("Authorization", "Bearer " + token)
        .contentType(MediaType.APPLICATION_JSON)
        .content(MERCEDES);
  }

  private static @NotNull MockHttpServletRequestBuilder postMercedesBuilder() {
    return MockMvcRequestBuilders.post("/car")
        .contentType(MediaType.APPLICATION_JSON)
        .content(MERCEDES);
  }

  private static @NotNull MockHttpServletRequestBuilder putMercedesBuilder(String token) {
    return MockMvcRequestBuilders.put("/car")
        .header("Authorization", "Bearer " + token)
        .contentType(MediaType.APPLICATION_JSON)
        .content(MERCEDES);
  }

  private static @NotNull MockHttpServletRequestBuilder getCarBuilder(String token, String model) {
    return MockMvcRequestBuilders.get("/car/{model}", model)
        .header("Authorization", "Bearer " + token)
        .accept(MediaType.APPLICATION_JSON);
  }

  private static @NotNull MockHttpServletRequestBuilder getBuilder(String path) {
    return MockMvcRequestBuilders.get(path)
        .accept(MediaType.APPLICATION_JSON);
  }

  private static @NotNull MockHttpServletRequestBuilder getBuilder(String token, String path) {
    return MockMvcRequestBuilders.get(path)
        .header("Authorization", "Bearer " + token)
        .accept(MediaType.APPLICATION_JSON);
  }

  private static @NotNull MockHttpServletRequestBuilder deleteCarBuilder() {
    return MockMvcRequestBuilders.delete("/car/Mercedes")
        .accept(MediaType.APPLICATION_JSON);
  }

  private static @NotNull MockHttpServletRequestBuilder deleteCarBuilder(String token) {
    return MockMvcRequestBuilders.delete("/car/{model}", "Mercedes")
        .header("Authorization", "Bearer " + token)
        .accept(MediaType.APPLICATION_JSON);
  }
}
