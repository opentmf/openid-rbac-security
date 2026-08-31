package org.opentmf.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.opentmf.security.util.TokenUtil.READ_TOKEN;
import static org.opentmf.security.util.TokenUtil.WRITE_TOKEN;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/**
 * Covers the servlet behaviour matrix for a denied request whose HTTP method the application
 * does or does not serve, with {@code unmatched-method-response} at its default.
 *
 * <p>The test controller serves {@code GET|POST|PUT /car}, {@code GET|DELETE /car/{name}} and
 * {@code GET /protectedButNotConfigured}. {@code /whitelist} is blacklisted here so that
 * suppression can be told apart from a genuine {@code 405}.
 *
 * @author Gokhan Demir
 */
@SpringBootTest(properties = "opentmf.security.blacklist[0]=/whitelist/**")
@AutoConfigureMockMvc
@ActiveProfiles({"servlet", "local"})
@TestInstance(Lifecycle.PER_CLASS)
class ServletMethodSemanticsIT {

  @Autowired WebApplicationContext context;
  MockMvc mockMvc;

  @BeforeAll
  void beforeAll() {
    mockMvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
  }

  // ---------------------------------------------------------------- item 2: 405

  @Test
  void unimplementedMethodOnServedPath_returnsMethodNotAllowedWithAllow() throws Exception {
    MvcResult result = mockMvc.perform(authorized(MockMvcRequestBuilders.patch("/car"))).andReturn();

    assertThat(result.getResponse().getStatus()).isEqualTo(405);
    assertThat(allowOf(result)).containsExactlyInAnyOrder("GET", "POST", "PUT");
  }

  /**
   * The case reported from the field: a {@code PUT} against a resource that only supports
   * {@code GET} and {@code DELETE} is an existence answer, not an authorization one.
   */
  @Test
  void unimplementedMethodOnTemplatedPath_returnsMethodNotAllowedWithAllow() throws Exception {
    MvcResult result =
        mockMvc.perform(authorized(MockMvcRequestBuilders.put("/car/Mercedes"))).andReturn();

    assertThat(result.getResponse().getStatus()).isEqualTo(405);
    assertThat(allowOf(result)).containsExactlyInAnyOrder("GET", "DELETE");
  }

  @Test
  void methodNotAllowedResponse_carriesNoBody() throws Exception {
    MvcResult result = mockMvc.perform(authorized(MockMvcRequestBuilders.patch("/car"))).andReturn();

    assertThat(result.getResponse().getContentAsString()).isEmpty();
  }

  @Test
  void unimplementedMethodOnPathWithNoRuleOfItsOwn_returnsMethodNotAllowed() throws Exception {
    MvcResult result = mockMvc
        .perform(authorized(MockMvcRequestBuilders.put("/protectedButNotConfigured")))
        .andReturn();

    assertThat(result.getResponse().getStatus()).isEqualTo(405);
    assertThat(allowOf(result)).containsExactly("GET");
  }

  // ------------------------------------------- the denials that must STAY denials

  /**
   * The load-bearing case. {@code DELETE /car/{name}} <em>is</em> implemented, and the access
   * rules withhold it from a read-only caller. That is an authorization answer, and relabelling
   * it {@code 405} would claim the endpoint does not exist when it does.
   */
  @Test
  void implementedMethodWithoutTheRole_staysForbidden() throws Exception {
    MvcResult result = mockMvc
        .perform(MockMvcRequestBuilders.delete("/car/Mercedes").header("Authorization", "Bearer " + READ_TOKEN))
        .andReturn();

    assertThat(result.getResponse().getStatus()).isEqualTo(403);
    assertThat(result.getResponse().getHeader(HttpHeaders.ALLOW)).isNull();
  }

  @Test
  void implementedMethodWithNoRuleAtAll_staysForbidden() throws Exception {
    MvcResult result = mockMvc
        .perform(authorized(MockMvcRequestBuilders.get("/protectedButNotConfigured")))
        .andReturn();

    assertThat(result.getResponse().getStatus()).isEqualTo(403);
    assertThat(result.getResponse().getHeader(HttpHeaders.ALLOW)).isNull();
  }

  @Test
  void pathNoControllerServes_staysForbidden() throws Exception {
    MvcResult result =
        mockMvc.perform(authorized(MockMvcRequestBuilders.put("/nothing/here"))).andReturn();

    assertThat(result.getResponse().getStatus()).isEqualTo(403);
    assertThat(result.getResponse().getHeader(HttpHeaders.ALLOW)).isNull();
  }

  /** A blacklisted path answers uniformly and discloses nothing about what it implements. */
  @Test
  void blacklistedPath_staysForbiddenWithoutAllow() throws Exception {
    MvcResult result =
        mockMvc.perform(authorized(MockMvcRequestBuilders.put("/whitelist"))).andReturn();

    assertThat(result.getResponse().getStatus()).isEqualTo(403);
    assertThat(result.getResponse().getHeader(HttpHeaders.ALLOW)).isNull();
  }

  /** Without a token the answer stays {@code 401}, so the method surface needs one to be seen. */
  @Test
  void unimplementedMethodWithoutToken_staysUnauthorized() throws Exception {
    MvcResult result = mockMvc.perform(MockMvcRequestBuilders.patch("/car")).andReturn();

    assertThat(result.getResponse().getStatus()).isEqualTo(401);
    assertThat(result.getResponse().getHeader(HttpHeaders.ALLOW)).isNull();
  }

  // ---------------------------------------------------------------- item 3: OPTIONS

  @Test
  void optionsOnServedPath_returnsOkWithAllow() throws Exception {
    MvcResult result =
        mockMvc.perform(authorized(MockMvcRequestBuilders.options("/car"))).andReturn();

    assertThat(result.getResponse().getStatus()).isEqualTo(200);
    assertThat(allowOf(result)).containsExactlyInAnyOrder("GET", "HEAD", "POST", "PUT", "OPTIONS");
  }

  // ---------------------------------------------------------------- item 1: HEAD

  @Test
  void headOnPathAllowedForGet_isServed() throws Exception {
    MvcResult result = mockMvc.perform(MockMvcRequestBuilders.head("/car")).andReturn();

    assertThat(result.getResponse().getStatus()).isEqualTo(200);
  }

  @Test
  void headOnPathSecuredForGet_isServedForACallerWithTheRole() throws Exception {
    mockMvc.perform(authorized(MockMvcRequestBuilders.post("/car"))
        .contentType(MediaType.APPLICATION_JSON)
        .content("{\"model\":\"Skoda\",\"color\":\"Green\",\"builtYear\":2023}"));

    MvcResult result = mockMvc
        .perform(MockMvcRequestBuilders.head("/car/Skoda").header("Authorization", "Bearer " + READ_TOKEN))
        .andReturn();

    assertThat(result.getResponse().getStatus()).isEqualTo(200);
  }

  @Test
  void headWithoutTheRole_staysForbidden() throws Exception {
    MvcResult result = mockMvc.perform(MockMvcRequestBuilders.head("/car/Skoda")).andReturn();

    assertThat(result.getResponse().getStatus()).isEqualTo(401);
  }

  private static MockHttpServletRequestBuilder authorized(MockHttpServletRequestBuilder builder) {
    return builder.header("Authorization", "Bearer " + WRITE_TOKEN);
  }

  private static Set<String> allowOf(MvcResult result) {
    String header = result.getResponse().getHeader(HttpHeaders.ALLOW);
    assertThat(header).isNotNull();
    return Arrays.stream(header.split(",")).map(String::trim).collect(Collectors.toSet());
  }
}
