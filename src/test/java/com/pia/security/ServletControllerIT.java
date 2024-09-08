package com.pia.security;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.pia.security.jwt.JwtService;
import com.pia.security.model.PiaSecurityProperties;
import com.pia.security.service.TokenService;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import java.io.IOException;
import java.net.URI;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("servlet")
@Slf4j
@AutoConfigureMockMvc
@TestInstance(Lifecycle.PER_CLASS)
class ServletControllerIT {

  static {
    @SuppressWarnings("resource")
    KeycloakContainer keycloakContainer = new KeycloakContainer().withRealmImportFile(
        "realm/rehearsal-realm.json");
    keycloakContainer.setPortBindings(List.of("8092:8080"));
    keycloakContainer.start();
  }

  @Autowired private SecurityFilterChain servletSecurityFilterChain;
  @Autowired private TokenService servletTokenService;
  @Autowired private PiaSecurityProperties piaSecurityProperties;
  @Autowired private JwtService jwtService;

  @Autowired private MockMvc mockMvc;
  @Autowired private WebApplicationContext context;

  @BeforeAll
  void beforeAll() {
    mockMvc = MockMvcBuilders.webAppContextSetup(context)
        .apply(springSecurity())
        .build();
  }

  @Test
  void contextLoads() {
    Assertions.assertNotNull(servletSecurityFilterChain);
    Assertions.assertNotNull(servletTokenService);
    Assertions.assertNotNull(piaSecurityProperties);
    Assertions.assertNotNull(jwtService);
  }

  private static final String MERCEDES = """
      {
        "model":"Mercedes",
        "color":"Green",
        "builtYear":2023
      }
      """;

  @Test
  void testPost_withValidToken_returnsCreated() throws Exception {
    String token = servletTokenService.getToken(getTokenUri(), "write");
    Assertions.assertNotNull(token);
    mockMvc.perform(postMercedesBuilder(token)).andExpect(status().isCreated());
  }

  @Test
  void testPost_withoutNecessaryAuthorities_returnsForbidden() throws Exception {
    String token = servletTokenService.getToken(getTokenUri(), "read");
    Assertions.assertNotNull(token);
    mockMvc.perform(postMercedesBuilder(token)).andExpect(status().isForbidden());
  }

  @Test
  void testGetCars_withoutToken_returnsOk() throws Exception {
    mockMvc.perform(getBuilder("/car")).andExpect(status().isOk());
  }

  @Test
  void testGetWhitelist_withoutToken_returnsOk() throws Exception {
    mockMvc.perform(getBuilder("/whitelist")).andExpect(status().isOk());
  }

  @ParameterizedTest
  @ValueSource(strings = {"read", "write"})
  void testPutCarAndThenGet_withBothTokens_returnsOk(String tokenType) throws Exception {
    String writeToken = servletTokenService.getToken(getTokenUri(), "write");
    mockMvc.perform(putMercedesBuilder(writeToken)).andExpect(status().isOk());
    String token = servletTokenService.getToken(getTokenUri(), tokenType);
    mockMvc.perform(getCarBuilder(token, "Mercedes")).andExpect(status().isOk());
    mockMvc.perform(getCarBuilder(token, "nonexistent")).andExpect(status().isNotFound());
  }

  @Test
  void testProtectedResource_withoutToken_returnsUnauthenticated() throws Exception {
    mockMvc.perform(getBuilder("/car/model")).andExpect(status().isUnauthorized());
  }

  @Test
  void testProtectedButNotConfigured_withoutToken_returnsUnauthorized() throws Exception {
    mockMvc.perform(getBuilder("/protectedButNotConfigured")).andExpect(status().isUnauthorized());
  }

  @Test
  void testProtectedButNotConfigured_withToken_returnsForbidden() throws Exception {
    String token = servletTokenService.getToken(getTokenUri(), "write");
    mockMvc.perform(getBuilder(token, "/protectedButNotConfigured")).andExpect(status().isForbidden());
  }

  @Test
  void testJwtService_withValidToken_returnsValidResults() {
    var token = servletTokenService.getToken(getTokenUri(), "write");
    var jwt = jwtService.decodeJwt(token);
    var groups = jwt.getClaim("groups");
    Assertions.assertNotNull(groups);
    Assertions.assertFalse(jwtService.isExpiredToken(jwt));
  }

  private URI getTokenUri() {
    try {
      var jwkSetUri = piaSecurityProperties.getJwkSetUri().getURL().toString();
      return URI.create(jwkSetUri.substring(0, jwkSetUri.lastIndexOf('/') + 1) + "token");
    } catch (IOException e) {
      throw new IllegalArgumentException("jwk-set-uri is not a valid URL");
    }
  }

  private static @NotNull MockHttpServletRequestBuilder postMercedesBuilder(String token) {
    return MockMvcRequestBuilders.post("/car")
        .header("Authorization", "Bearer " + token)
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
}
