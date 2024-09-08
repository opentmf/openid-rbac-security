package com.pia.security;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

import com.pia.security.jwt.JwtService;
import com.pia.security.model.PiaSecurityProperties;
import com.pia.security.service.TokenService;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.reactive.server.WebTestClient;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("reactive-local")
@Slf4j
@TestInstance(Lifecycle.PER_CLASS)
class ReactiveControllerLocalJwkSetIT {

  @Autowired private SecurityWebFilterChain reactiveSecurityFilterChain;
  @Autowired private TokenService reactiveTokenService;
  @Autowired private PiaSecurityProperties piaSecurityProperties;
  @Autowired private JwtService jwtService;

  @Autowired private ApplicationContext applicationContext;

  @BeforeAll
  void beforeAll() {
    WebTestClient
        .bindToApplicationContext(applicationContext)
        .apply(springSecurity())
        .configureClient()
        .build();
  }

  @Test
  void contextLoads() {
    assertNotNull(reactiveSecurityFilterChain);
    assertNotNull(reactiveTokenService);
    assertNotNull(piaSecurityProperties);
    assertNotNull(jwtService);
  }
}
