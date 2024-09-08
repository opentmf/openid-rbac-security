package com.pia.security;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;

import com.pia.security.jwt.JwtService;
import com.pia.security.model.PiaSecurityProperties;
import com.pia.security.service.TokenService;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("servlet")
@Slf4j
@AutoConfigureMockMvc
@TestInstance(Lifecycle.PER_CLASS)
class ServletControllerLocalJwkSetIT {

  @Autowired private SecurityFilterChain servletSecurityFilterChain;
  @Autowired private TokenService servletTokenService;
  @Autowired private PiaSecurityProperties piaSecurityProperties;
  @Autowired private JwtService jwtService;

  @Autowired private WebApplicationContext context;

  @BeforeAll
  void beforeAll() {
    MockMvcBuilders.webAppContextSetup(context)
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
}
