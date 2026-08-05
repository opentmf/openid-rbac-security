package org.opentmf.security;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.opentmf.security.util.TestIssuer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Regression for the 2.2.0 hook under multi-issuer wiring: choosing the decoder by issuer
 * happens through an {@code AuthenticationManagerResolver}, which Spring Security treats as an
 * alternative to {@code jwt()} — so this proves the consumer-supplied 401/403 handlers, which
 * live on the same configurer, keep being applied on both failure paths.
 *
 * @author Gokhan Demir
 */
@SpringBootTest(properties = "spring.main.web-application-type=servlet")
@AutoConfigureMockMvc
class ServletMultiIssuerCustomHandlersIT {

  static final TestIssuer ISSUER =
      TestIssuer.create("handlers", "https://handlers.example.test/v2.0");
  static final String CUSTOM_401_BODY = "{\"status\":\"401\",\"message\":\"custom-unauthorized\"}";
  static final String CUSTOM_403_BODY = "{\"status\":\"403\",\"message\":\"custom-forbidden\"}";

  @Autowired MockMvc mockMvc;

  @DynamicPropertySource
  static void trustOneIssuer(DynamicPropertyRegistry registry) {
    registry.add("opentmf.security.issuers[0].name", () -> "handlers");
    registry.add("opentmf.security.issuers[0].issuer", ISSUER::getIssuer);
    registry.add("opentmf.security.issuers[0].jwk-set-uri", ISSUER::getJwkSetUri);
    registry.add("opentmf.security.issuers[0].authorities-claim", () -> "roles");
  }

  @TestConfiguration(proxyBeanMethods = false)
  static class CustomHandlerConfig {

    @Bean
    AuthenticationEntryPoint customEntryPoint() {
      return (request, response, exception) ->
          writeJson(response, HttpStatus.UNAUTHORIZED, CUSTOM_401_BODY);
    }

    @Bean
    AccessDeniedHandler customAccessDeniedHandler() {
      return (request, response, exception) ->
          writeJson(response, HttpStatus.FORBIDDEN, CUSTOM_403_BODY);
    }

    private static void writeJson(HttpServletResponse response, HttpStatus status, String body)
        throws IOException {
      response.setStatus(status.value());
      response.setContentType(MediaType.APPLICATION_JSON_VALUE);
      response.getWriter().write(body);
    }
  }

  @Test
  void noToken_stillRendersTheCustom401() throws Exception {
    mockMvc.perform(get("/car/never-created"))
        .andExpect(status().isUnauthorized())
        .andExpect(content().string(CUSTOM_401_BODY));
  }

  @Test
  void unknownIssuer_rendersTheCustom401() throws Exception {
    String token = ISSUER.mintWithIssuer("https://attacker.example.test/v2.0",
        claims -> claims.claim("roles", List.of("write")));

    mockMvc.perform(get("/car/never-created").header("Authorization", "Bearer " + token))
        .andExpect(status().isUnauthorized())
        .andExpect(content().string(CUSTOM_401_BODY));
  }

  @Test
  void insufficientRole_rendersTheCustom403() throws Exception {
    String token = ISSUER.mint(claims -> claims.claim("roles", List.of("read")));

    mockMvc.perform(post("/car")
            .header("Authorization", "Bearer " + token)
            .contentType(MediaType.APPLICATION_JSON)
            .content(BaseIT.MERCEDES))
        .andExpect(status().isForbidden())
        .andExpect(content().string(CUSTOM_403_BODY));
  }
}
