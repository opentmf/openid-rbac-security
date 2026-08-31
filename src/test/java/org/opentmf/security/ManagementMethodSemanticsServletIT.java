package org.opentmf.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.opentmf.security.util.TokenUtil.WRITE_TOKEN;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.Ordered;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalManagementPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

/**
 * The management port answers method semantics from the <em>management</em> context's handler
 * mappings, not the main context's.
 *
 * <p>On the servlet stack this is the case most easily got wrong: the management chain is
 * registered in the main {@code ApplicationContext} (Boot exposes the parent's filter chain on
 * the management port), while the actuator endpoints it guards are mapped in the management
 * child context. Consulting the wrong one would advertise the business API's methods on the
 * management port. {@code /car} exists on the main port and nowhere on this one, so a denied
 * request for it here must answer {@code 403} — never a {@code 405} naming the main port's verbs.
 *
 * <p>Runs with {@code management.other-endpoints: DENY}, since the default of
 * {@code AUTHENTICATED} lets unmatched requests through to the actuator, where the question does
 * not arise.
 *
 * @author Gokhan Demir
 */
@SpringBootTest(
    webEnvironment = WebEnvironment.RANDOM_PORT,
    properties = {
        "server.servlet.context-path=/opentmf/commons",
        "management.server.port=0",
        "management.endpoints.web.exposure.include=health,info,metrics",
        "opentmf.security.management.other-endpoints=DENY",
        "opentmf.security.management.secure-endpoints[0].method=GET",
        "opentmf.security.management.secure-endpoints[0].path=/actuator/metrics",
        "opentmf.security.management.secure-endpoints[0].roles=write"
    })
@ActiveProfiles({"servlet", "local"})
@TestInstance(Lifecycle.PER_CLASS)
@Import(ManagementMethodSemanticsServletIT.LeakProbeConfig.class)
class ManagementMethodSemanticsServletIT {

  private static final ResponseErrorHandler NEVER_ERROR = response -> false;

  /**
   * A second, differently named handler mapping in the MAIN context. Real applications grow
   * these — Spring Integration's {@code integrationRequestMappingHandlerMapping}, or a second
   * mapping for a versioned API. It matters because Boot's management child context shadows the
   * parent's {@code requestMappingHandlerMapping} only by sharing its bean <em>name</em>: a
   * mapping under any other name is invisible to that shadowing, and a lookup that walks into
   * ancestors would pull it into the management port's answer.
   */
  @TestConfiguration(proxyBeanMethods = false)
  static class LeakProbeConfig {

    @Bean
    LeakProbeController leakProbeController() {
      return new LeakProbeController();
    }

    @Bean
    RequestMappingHandlerMapping leakProbeRequestMappingHandlerMapping() {
      RequestMappingHandlerMapping mapping = new RequestMappingHandlerMapping() {
        @Override
        protected boolean isHandler(Class<?> beanType) {
          return LeakProbeController.class.equals(beanType);
        }
      };
      mapping.setOrder(Ordered.LOWEST_PRECEDENCE - 1);
      return mapping;
    }
  }

  /** Deliberately not a {@code @RestController}, so only the probe mapping above picks it up. */
  static class LeakProbeController {

    @GetMapping("/leak-probe")
    String probe() {
      return "probe";
    }
  }

  @LocalManagementPort int managementPort;
  RestTemplate restTemplate;

  @BeforeAll
  void beforeAll() {
    // The JDK's HttpURLConnection rejects PATCH outright, and PATCH is the verb that tells a
    // context leak apart from an ordinary denial here.
    restTemplate = new RestTemplate(new JdkClientHttpRequestFactory());
    restTemplate.setErrorHandler(NEVER_ERROR);
  }

  @Test
  void unimplementedMethodOnAnActuatorPath_returnsMethodNotAllowedWithAllow() {
    ResponseEntity<String> response = exchange(HttpMethod.PUT, "/actuator/metrics");

    assertThat(response.getStatusCode().value()).isEqualTo(405);
    assertThat(allowOf(response)).contains("GET");
  }

  /**
   * The main port's controllers must not be visible from here.
   *
   * <p>{@code PATCH}, not {@code PUT}: {@code /car} implements {@code PUT}, so a {@code PUT}
   * would be left at {@code 403} by the "the code implements this verb" rule whether or not the
   * main context leaked in — it cannot tell the two apart. Nothing implements {@code PATCH} on
   * {@code /car}, so a leak would surface as {@code 405} naming the main API's verbs.
   */
  @Test
  void aPathServedOnlyByTheMainPort_staysForbidden() {
    ResponseEntity<String> response = exchange(HttpMethod.PATCH, "/car");

    assertThat(response.getStatusCode().value()).isEqualTo(403);
    assertThat(response.getHeaders().getFirst(HttpHeaders.ALLOW)).isNull();
  }

  /**
   * The discriminating case: a mapping in the main context under a name the child does not
   * shadow. A lookup that walks into ancestor contexts answers {@code 405} with
   * {@code Allow: GET} here; a local-only lookup leaves the denial at {@code 403}.
   */
  @Test
  void aMappingNamedOnlyInTheMainContext_doesNotReachTheManagementPort() {
    ResponseEntity<String> response = exchange(HttpMethod.PUT, "/leak-probe");

    assertThat(response.getStatusCode().value()).isEqualTo(403);
    assertThat(response.getHeaders().getFirst(HttpHeaders.ALLOW)).isNull();
  }

  @Test
  void unimplementedMethodWithoutToken_staysUnauthorized() {
    HttpHeaders headers = new HttpHeaders();
    ResponseEntity<String> response = restTemplate.exchange(
        managementUri("/actuator/metrics"), HttpMethod.PUT, new HttpEntity<>(headers), String.class);

    assertThat(response.getStatusCode().value()).isEqualTo(401);
    assertThat(response.getHeaders().getFirst(HttpHeaders.ALLOW)).isNull();
  }

  private ResponseEntity<String> exchange(HttpMethod method, String path) {
    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(WRITE_TOKEN);
    return restTemplate.exchange(
        managementUri(path), method, new HttpEntity<>(headers), String.class);
  }

  private String managementUri(String path) {
    return "http://localhost:" + managementPort + path;
  }

  private static Set<String> allowOf(ResponseEntity<String> response) {
    String header = response.getHeaders().getFirst(HttpHeaders.ALLOW);
    assertThat(header).isNotNull();
    return Arrays.stream(header.split(",")).map(String::trim).collect(Collectors.toSet());
  }
}
