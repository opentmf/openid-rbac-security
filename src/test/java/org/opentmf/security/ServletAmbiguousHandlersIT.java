package org.opentmf.security;

import static org.opentmf.security.util.TokenUtil.READ_TOKEN;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Pins the ambiguity fallback: with TWO candidate {@link AuthenticationEntryPoint} beans (and no
 * {@code @Primary}), the library refuses to guess and keeps the Spring Security default 401 —
 * while the unambiguous {@link AccessDeniedHandler} bean is still applied independently. The WARN
 * that names both candidates is asserted in {@code UniqueBeanResolverTest}; this IT pins the
 * runtime behavior. Uses the file-based JWK set so the test does not require Docker / Keycloak.
 *
 * @author Gokhan Demir
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"servlet", "local"})
class ServletAmbiguousHandlersIT {

  static final String FIRST_BODY = "{\"source\":\"first-entry-point\"}";
  static final String SECOND_BODY = "{\"source\":\"second-entry-point\"}";
  static final String CUSTOM_403_BODY = "{\"status\":\"403\",\"message\":\"custom-forbidden\"}";

  @Autowired MockMvc mockMvc;

  @TestConfiguration(proxyBeanMethods = false)
  static class AmbiguousHandlerConfig {

    @Bean
    AuthenticationEntryPoint firstEntryPoint() {
      return (request, response, exception) -> {
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.getWriter().write(FIRST_BODY);
      };
    }

    @Bean
    AuthenticationEntryPoint secondEntryPoint() {
      return (request, response, exception) -> {
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.getWriter().write(SECOND_BODY);
      };
    }

    @Bean
    AccessDeniedHandler unambiguousAccessDeniedHandler() {
      return (request, response, exception) -> {
        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(CUSTOM_403_BODY);
      };
    }
  }

  @Test
  void ambiguousEntryPoints_fallBackToDefault401() throws Exception {
    mockMvc.perform(get("/car/model"))
        .andExpect(status().isUnauthorized())
        .andExpect(header().exists("WWW-Authenticate"))
        .andExpect(content().string(""));
  }

  @Test
  void unambiguousAccessDeniedHandler_isStillApplied() throws Exception {
    mockMvc.perform(post("/car")
            .header("Authorization", "Bearer " + READ_TOKEN)
            .contentType(MediaType.APPLICATION_JSON)
            .content(BaseIT.MERCEDES))
        .andExpect(status().isForbidden())
        .andExpect(content().string(CUSTOM_403_BODY));
  }
}
