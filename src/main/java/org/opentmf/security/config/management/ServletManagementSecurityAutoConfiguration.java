package org.opentmf.security.config.management;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

import jakarta.servlet.http.HttpServletRequest;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.opentmf.security.config.EndpointRules;
import org.opentmf.security.config.MethodNotAllowedAccessDeniedHandler;
import org.opentmf.security.config.ServletBlacklistDenial;
import org.opentmf.security.config.ServletJwtAutoConfiguration;
import org.opentmf.security.config.ServletJwtSupport;
import org.opentmf.security.config.ServletSupportedMethodsResolver;
import org.opentmf.security.model.OpenTmfSecurityProperties;
import org.opentmf.security.model.OpenTmfSecurityProperties.Management;
import org.opentmf.security.model.OtherEndpoints;
import org.opentmf.security.model.UnmatchedMethodResponse;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.boot.web.server.context.WebServerInitializedEvent;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.event.EventListener;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.HttpBasicConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.web.servlet.mvc.method.RequestMappingInfoHandlerMapping;

/**
 * Registers a JWT-authenticated {@link SecurityFilterChain} for the management port into the
 * MAIN {@code ApplicationContext}, matched by the request's local port.
 *
 * <p>Living in the main context (rather than the management child context) is deliberate: on a
 * separate management port, Spring Boot's {@code ServletManagementChildContextConfiguration}
 * exposes the PARENT context's {@code springSecurityFilterChain} inside the child context,
 * overriding anything an {@code @EnableWebSecurity} setup in the child would build. A chain
 * registered in the child is therefore never consulted — the management port is always served by
 * the parent's {@code FilterChainProxy}. So the management chain must be one of the parent's
 * chains, scoped to the management port.
 *
 * <p>The management port is captured from the management child context's
 * {@link WebServerInitializedEvent} (child-context events propagate to the parent, and the child
 * carries the {@code management} server namespace), which also works for a random port
 * ({@code management.server.port: 0}). Until that event arrives no request can reach the
 * management server, so the matcher's initial empty state never matches a real request.
 *
 * @author Gokhan Demir
 */
@AutoConfiguration(after = ServletJwtAutoConfiguration.class)
@Conditional(OnSeparateManagementPortCondition.class)
@ConditionalOnClass({SecurityFilterChain.class, HttpSecurity.class})
@ConditionalOnWebApplication(type = Type.SERVLET)
@RequiredArgsConstructor
@Slf4j
public class ServletManagementSecurityAutoConfiguration {

  static final String MANAGEMENT_SERVER_NAMESPACE = "management";

  private final OpenTmfSecurityProperties properties;
  private final ServletJwtSupport servletJwtSupport;

  /**
   * The management server's {@link WebServerInitializedEvent}, kept whole: the port and the
   * child context arrive together in it, and storing them as one reference makes
   * "port matched but context missing" unrepresentable, rather than a write-ordering rule a
   * future edit could break.
   */
  private final AtomicReference<WebServerInitializedEvent> managementServer =
      new AtomicReference<>();

  @EventListener
  void captureManagementPort(WebServerInitializedEvent event) {
    if (MANAGEMENT_SERVER_NAMESPACE.equals(event.getApplicationContext().getServerNamespace())) {
      managementServer.set(event);
    }
  }

  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  SecurityFilterChain managementSecurityFilterChain(HttpSecurity http) {
    log.info("Registering JWT-authenticated SecurityFilterChain for the management port.");
    return http
        .securityMatcher(this::isManagementPortRequest)
        .sessionManagement(session -> session.sessionCreationPolicy(STATELESS))
        .csrf(CsrfConfigurer::disable)
        .formLogin(FormLoginConfigurer::disable)
        .httpBasic(HttpBasicConfigurer::disable)
        .logout(LogoutConfigurer::disable)
        .authorizeHttpRequests(this::applyManagementAuthorization)
        .exceptionHandling(this::configureDeniedHandler)
        .oauth2ResourceServer(this::configureResourceServer)
        .build();
  }

  private boolean isManagementPortRequest(HttpServletRequest request) {
    WebServerInitializedEvent event = managementServer.get();
    return event != null && request.getLocalPort() == event.getWebServer().getPort();
  }

  private void configureResourceServer(OAuth2ResourceServerConfigurer<HttpSecurity> oauth2) {
    servletJwtSupport.apply(oauth2);
  }

  /**
   * Installs the denied-request handler on the {@code exceptionHandling} slot — which covers
   * every authorization denial on this port, however the caller authenticated — so that a
   * request for a method the actuator does not serve on that path is answered {@code 405}
   * rather than {@code 403}, honouring the management section's own
   * {@code unmatched-method-response}.
   */
  private void configureDeniedHandler(ExceptionHandlingConfigurer<HttpSecurity> handling) {
    if (properties.getManagement().getUnmatchedMethodResponse()
        == UnmatchedMethodResponse.METHOD_NOT_ALLOWED) {
      handling.accessDeniedHandler(new MethodNotAllowedAccessDeniedHandler(
          new BearerTokenAccessDeniedHandler(),
          new ServletSupportedMethodsResolver(this::managementHandlerMappings)));
    }
  }

  /**
   * The handler mappings of the management child context — the one that actually dispatches
   * management-port requests. This chain lives in the main context (see the class javadoc), so
   * the main context's own mappings are the wrong ones to consult: they describe the business
   * API, not the actuator, and answering a management-port request from them would advertise
   * methods that port does not serve. The child context is captured from the same
   * {@link WebServerInitializedEvent} the port comes from, and read only on the first denial,
   * long after that event.
   */
  private Stream<RequestMappingInfoHandlerMapping> managementHandlerMappings() {
    WebServerInitializedEvent event = managementServer.get();
    if (event == null) {
      // Not ready yet. Throwing rather than returning an empty stream matters: the resolver
      // caches its snapshot on first success and SingletonSupplier caches successes but not
      // failures, so an empty snapshot taken during startup would disable this port's method
      // semantics for the life of the process. A throw costs one denial and is retried.
      throw new IllegalStateException("The management context has not been initialized yet.");
    }
    // getBeansOfType, not getBeanProvider().stream(): the latter walks into ancestor contexts
    // and excludes a parent bean only when the child happens to define one under the same name.
    // The main context's mappings describe the business API, and answering a management-port
    // denial from them would advertise verbs this port does not serve.
    return event.getApplicationContext()
        .getBeansOfType(RequestMappingInfoHandlerMapping.class)
        .values()
        .stream();
  }

  private void applyManagementAuthorization(
      AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry
          requests) {
    Management management = properties.getManagement();
    var blacklistDenial = new ServletBlacklistDenial();
    management.getBlacklist().forEach(path ->
        requests.requestMatchers(path).access(blacklistDenial));
    management.getWhitelist().forEach(path -> requests.requestMatchers(path).permitAll());
    management.getAllowedEndpoints().forEach(endpoint -> {
      for (HttpMethod method : EndpointRules.httpMethodsFor(endpoint)) {
        requests.requestMatchers(method, endpoint.getPath()).permitAll();
      }
    });
    management.getSecureEndpoints().forEach(endpoint -> {
      for (HttpMethod method : EndpointRules.httpMethodsFor(endpoint)) {
        requests.requestMatchers(method, endpoint.getPath()).hasAnyAuthority(endpoint.getRoles());
      }
    });
    OtherEndpoints policy = management.getOtherEndpoints();
    switch (policy) {
      case ALLOW -> requests.anyRequest().permitAll();
      case DENY -> requests.anyRequest().denyAll();
      case AUTHENTICATED -> requests.anyRequest().authenticated();
    }
  }
}
