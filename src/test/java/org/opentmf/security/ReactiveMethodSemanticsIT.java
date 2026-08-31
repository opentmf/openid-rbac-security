package org.opentmf.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.opentmf.security.util.TokenUtil.READ_TOKEN;
import static org.opentmf.security.util.TokenUtil.WRITE_TOKEN;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.reactive.server.EntityExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;

/**
 * The reactive twin of {@link ServletMethodSemanticsIT}; see that class for what each case
 * stands for.
 *
 * @author Gokhan Demir
 */
@SpringBootTest(properties = "opentmf.security.blacklist[0]=/whitelist/**")
@ActiveProfiles({"reactive", "local"})
@TestInstance(Lifecycle.PER_CLASS)
class ReactiveMethodSemanticsIT {

  @Autowired ApplicationContext applicationContext;
  WebTestClient webTestClient;

  @BeforeAll
  void beforeAll() {
    webTestClient = WebTestClient
        .bindToApplicationContext(applicationContext)
        .apply(springSecurity())
        .configureClient()
        .build();
  }

  // ---------------------------------------------------------------- item 2: 405

  @Test
  void unimplementedMethodOnServedPath_returnsMethodNotAllowedWithAllow() {
    EntityExchangeResult<byte[]> result = exchange(HttpMethod.PATCH, "/car", WRITE_TOKEN);

    assertThat(result.getStatus().value()).isEqualTo(405);
    assertThat(allowOf(result)).containsExactlyInAnyOrder("GET", "POST", "PUT");
  }

  @Test
  void unimplementedMethodOnTemplatedPath_returnsMethodNotAllowedWithAllow() {
    EntityExchangeResult<byte[]> result = exchange(HttpMethod.PUT, "/car/Mercedes", WRITE_TOKEN);

    assertThat(result.getStatus().value()).isEqualTo(405);
    assertThat(allowOf(result)).containsExactlyInAnyOrder("GET", "DELETE");
  }

  @Test
  void methodNotAllowedResponse_carriesNoBody() {
    EntityExchangeResult<byte[]> result = exchange(HttpMethod.PATCH, "/car", WRITE_TOKEN);

    assertThat(result.getResponseBody()).isNull();
  }

  @Test
  void unimplementedMethodOnPathWithNoRuleOfItsOwn_returnsMethodNotAllowed() {
    EntityExchangeResult<byte[]> result =
        exchange(HttpMethod.PUT, "/protectedButNotConfigured", WRITE_TOKEN);

    assertThat(result.getStatus().value()).isEqualTo(405);
    assertThat(allowOf(result)).containsExactly("GET");
  }

  // ------------------------------------------- the denials that must STAY denials

  @Test
  void implementedMethodWithoutTheRole_staysForbidden() {
    EntityExchangeResult<byte[]> result = exchange(HttpMethod.DELETE, "/car/Mercedes", READ_TOKEN);

    assertThat(result.getStatus().value()).isEqualTo(403);
    assertThat(result.getResponseHeaders().getFirst(HttpHeaders.ALLOW)).isNull();
  }

  @Test
  void implementedMethodWithNoRuleAtAll_staysForbidden() {
    EntityExchangeResult<byte[]> result =
        exchange(HttpMethod.GET, "/protectedButNotConfigured", WRITE_TOKEN);

    assertThat(result.getStatus().value()).isEqualTo(403);
    assertThat(result.getResponseHeaders().getFirst(HttpHeaders.ALLOW)).isNull();
  }

  @Test
  void pathNoControllerServes_staysForbidden() {
    EntityExchangeResult<byte[]> result = exchange(HttpMethod.PUT, "/nothing/here", WRITE_TOKEN);

    assertThat(result.getStatus().value()).isEqualTo(403);
    assertThat(result.getResponseHeaders().getFirst(HttpHeaders.ALLOW)).isNull();
  }

  @Test
  void blacklistedPath_staysForbiddenWithoutAllow() {
    EntityExchangeResult<byte[]> result = exchange(HttpMethod.PUT, "/whitelist", WRITE_TOKEN);

    assertThat(result.getStatus().value()).isEqualTo(403);
    assertThat(result.getResponseHeaders().getFirst(HttpHeaders.ALLOW)).isNull();
  }

  @Test
  void unimplementedMethodWithoutToken_staysUnauthorized() {
    EntityExchangeResult<byte[]> result = exchange(HttpMethod.PATCH, "/car", null);

    assertThat(result.getStatus().value()).isEqualTo(401);
    assertThat(result.getResponseHeaders().getFirst(HttpHeaders.ALLOW)).isNull();
  }

  // ---------------------------------------------------------------- item 3: OPTIONS

  @Test
  void optionsOnServedPath_returnsOkWithAllow() {
    EntityExchangeResult<byte[]> result = exchange(HttpMethod.OPTIONS, "/car", WRITE_TOKEN);

    assertThat(result.getStatus().value()).isEqualTo(200);
    assertThat(allowOf(result)).containsExactlyInAnyOrder("GET", "HEAD", "POST", "PUT", "OPTIONS");
  }

  // ---------------------------------------------------------------- item 1: HEAD

  @Test
  void headOnPathAllowedForGet_isServed() {
    EntityExchangeResult<byte[]> result = exchange(HttpMethod.HEAD, "/car", null);

    assertThat(result.getStatus().value()).isEqualTo(200);
  }

  @Test
  void headOnPathSecuredForGet_isServedForACallerWithTheRole() {
    webTestClient.post().uri("/car")
        .header(HttpHeaders.AUTHORIZATION, "Bearer " + WRITE_TOKEN)
        .contentType(MediaType.APPLICATION_JSON)
        .bodyValue("{\"model\":\"Skoda\",\"color\":\"Green\",\"builtYear\":2023}")
        .exchange();

    EntityExchangeResult<byte[]> result = exchange(HttpMethod.HEAD, "/car/Skoda", READ_TOKEN);

    assertThat(result.getStatus().value()).isEqualTo(200);
  }

  @Test
  void headWithoutTheRole_staysUnauthorized() {
    EntityExchangeResult<byte[]> result = exchange(HttpMethod.HEAD, "/car/Skoda", null);

    assertThat(result.getStatus().value()).isEqualTo(401);
  }

  private EntityExchangeResult<byte[]> exchange(HttpMethod method, String path, String token) {
    WebTestClient.RequestBodySpec request = webTestClient.method(method).uri(path);
    if (token != null) {
      request.header(HttpHeaders.AUTHORIZATION, "Bearer " + token);
    }
    return request.exchange().expectBody().returnResult();
  }

  private static Set<String> allowOf(EntityExchangeResult<byte[]> result) {
    String header = result.getResponseHeaders().getFirst(HttpHeaders.ALLOW);
    assertThat(header).isNotNull();
    return Arrays.stream(header.split(",")).map(String::trim).collect(Collectors.toSet());
  }
}
