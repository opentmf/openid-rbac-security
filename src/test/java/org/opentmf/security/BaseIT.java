package org.opentmf.security;


import org.opentmf.security.jwt.JwtService;
import org.opentmf.security.model.OpenTmfSecurityProperties;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestInstance(Lifecycle.PER_CLASS)
@TestMethodOrder(OrderAnnotation.class)
@Slf4j
abstract class BaseIT {

  static final String MERCEDES = """
      {
        "model":"Mercedes",
        "color":"Green",
        "builtYear":2023
      }
      """;

  @Autowired
  OpenTmfSecurityProperties openTmfSecurityProperties;
  @Autowired JwtService jwtService;

  abstract String getToken(String scope);
}
