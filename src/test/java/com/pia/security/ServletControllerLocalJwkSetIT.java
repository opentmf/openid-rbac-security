package com.pia.security;

import static com.pia.security.util.TokenUtil.EXPIRED_READER_TOKEN;
import static com.pia.security.util.TokenUtil.WRITE_TOKEN;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.pia.security.jwt.JwtService;
import com.pia.security.model.PiaSecurityProperties;
import com.pia.security.service.TokenService;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
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
@ActiveProfiles("jwk-set")
@Slf4j
@AutoConfigureMockMvc
@TestInstance(Lifecycle.PER_CLASS)
class ServletControllerLocalJwkSetIT {

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

  @Test
  void testJwtService_withValidToken_returnsValidResults() throws Exception {
    Assertions.assertTrue(jwtService.isExpiredToken(EXPIRED_READER_TOKEN));
    mockMvc.perform(postMercedesBuilder())
        .andExpect(status().isCreated());
  }

  private static final String MERCEDES = """
      {
        "model":"Mercedes",
        "color":"Green",
        "builtYear":2023
      }
      """;

  private static @NotNull MockHttpServletRequestBuilder postMercedesBuilder() {
    return MockMvcRequestBuilders.post("/car")
        .header("Authorization", "Bearer " + WRITE_TOKEN)
        .contentType(MediaType.APPLICATION_JSON)
        .content(MERCEDES);
  }
}
