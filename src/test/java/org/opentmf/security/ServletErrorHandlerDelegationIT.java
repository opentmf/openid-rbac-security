package org.opentmf.security;

import static org.opentmf.security.util.TokenUtil.EXPIRED_TOKEN;
import static org.opentmf.security.util.TokenUtil.READ_TOKEN;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.http.MediaType;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.servlet.HandlerExceptionResolver;

/**
 * Proves the README's servlet "converge-on-one-place" recipe end-to-end: the entry point and
 * access-denied handler delegate to the {@code handlerExceptionResolver}, which routes security
 * failures into the {@code GlobalExceptionHandler} advice — so 401/403 render the exact same
 * {@code ErrorContext} shape as every other error. Uses the file-based JWK set so the test does
 * not require Docker / Keycloak.
 *
 * @author Gokhan Demir
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles({"servlet", "local"})
class ServletErrorHandlerDelegationIT {

  @Autowired MockMvc mockMvc;

  @TestConfiguration(proxyBeanMethods = false)
  static class DelegatingHandlerConfig {

    @Bean
    AuthenticationEntryPoint delegatingEntryPoint(
        @Qualifier("handlerExceptionResolver") HandlerExceptionResolver resolver) {
      return (request, response, exception) ->
          resolver.resolveException(request, response, null, exception);
    }

    @Bean
    AccessDeniedHandler delegatingAccessDeniedHandler(
        @Qualifier("handlerExceptionResolver") HandlerExceptionResolver resolver) {
      return (request, response, exception) ->
          resolver.resolveException(request, response, null, exception);
    }
  }

  @Test
  void noToken_rendersErrorContextFromAdvice() throws Exception {
    mockMvc.perform(get("/car/model"))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.status").value("401"))
        .andExpect(jsonPath("$.message").isNotEmpty());
  }

  @Test
  void invalidToken_rendersErrorContextFromAdvice() throws Exception {
    mockMvc.perform(get("/car/model").header("Authorization", "Bearer " + EXPIRED_TOKEN))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.status").value("401"))
        .andExpect(jsonPath("$.message").isNotEmpty());
  }

  @Test
  void insufficientRole_rendersErrorContextFromAdvice() throws Exception {
    mockMvc.perform(post("/car")
            .header("Authorization", "Bearer " + READ_TOKEN)
            .contentType(MediaType.APPLICATION_JSON)
            .content(BaseIT.MERCEDES))
        .andExpect(status().isForbidden())
        .andExpect(jsonPath("$.status").value("403"))
        .andExpect(jsonPath("$.message").isNotEmpty());
  }
}
