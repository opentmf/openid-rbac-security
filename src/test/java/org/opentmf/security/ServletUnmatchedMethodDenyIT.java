package org.opentmf.security;

import static org.assertj.core.api.Assertions.assertThat;
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
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/**
 * Two things at once, both needing {@code unmatched-method-response: DENY}.
 *
 * <p>First, the opt-out: with it set, every denial answers {@code 403} again, exactly as
 * releases before 3.0.0 did.
 *
 * <p>Second, and more valuable, the cross-check that keeps this feature honest. Here
 * {@code /protectedButNotConfigured} is whitelisted, so {@code PUT} against it is never denied
 * and reaches the dispatcher, where <em>Spring</em> produces the {@code 405}. The assertion
 * below records what Spring answers.
 * {@link ServletMethodSemanticsIT#unimplementedMethodOnPathWithNoRuleOfItsOwn_returnsMethodNotAllowed()}
 * asserts the same status and the same {@code Allow} for the same request when the security
 * chain denies it instead. If those two ever drift apart, one of them is wrong — and if a
 * Spring upgrade changes how the {@code Allow} header is computed, this test is what notices.
 *
 * @author Gokhan Demir
 */
@SpringBootTest(properties = {
    "opentmf.security.whitelist[0]=/protectedButNotConfigured",
    "opentmf.security.unmatched-method-response=DENY"
})
@AutoConfigureMockMvc
@ActiveProfiles({"servlet", "local"})
@TestInstance(Lifecycle.PER_CLASS)
class ServletUnmatchedMethodDenyIT {

  @Autowired WebApplicationContext context;
  MockMvc mockMvc;

  @BeforeAll
  void beforeAll() {
    mockMvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
  }

  @Test
  void springsOwnMethodNotAllowed_isWhatThisLibraryReproduces() throws Exception {
    MvcResult result =
        mockMvc.perform(MockMvcRequestBuilders.put("/protectedButNotConfigured")).andReturn();

    assertThat(result.getResponse().getStatus()).isEqualTo(405);
    assertThat(allowOf(result)).containsExactly("GET");
  }

  @Test
  void unimplementedMethod_answersForbiddenAgain() throws Exception {
    MvcResult result = mockMvc
        .perform(MockMvcRequestBuilders.put("/car/Mercedes").header("Authorization", "Bearer " + WRITE_TOKEN))
        .andReturn();

    assertThat(result.getResponse().getStatus()).isEqualTo(403);
    assertThat(result.getResponse().getHeader(HttpHeaders.ALLOW)).isNull();
  }

  @Test
  void plainOptions_answersForbiddenAgain() throws Exception {
    MvcResult result = mockMvc
        .perform(MockMvcRequestBuilders.options("/car").header("Authorization", "Bearer " + WRITE_TOKEN))
        .andReturn();

    assertThat(result.getResponse().getStatus()).isEqualTo(403);
    assertThat(result.getResponse().getHeader(HttpHeaders.ALLOW)).isNull();
  }

  /** The HEAD fix is not gated by the property, so it applies here too. */
  @Test
  void headOnPathAllowedForGet_isStillServed() throws Exception {
    MvcResult result = mockMvc.perform(MockMvcRequestBuilders.head("/car")).andReturn();

    assertThat(result.getResponse().getStatus()).isEqualTo(200);
  }

  private static Set<String> allowOf(MvcResult result) {
    String header = result.getResponse().getHeader(HttpHeaders.ALLOW);
    assertThat(header).isNotNull();
    return Arrays.stream(header.split(",")).map(String::trim).collect(Collectors.toSet());
  }
}
