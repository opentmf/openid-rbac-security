package org.opentmf.security.config.management;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

import jakarta.servlet.http.HttpServletRequest;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.opentmf.security.config.EndpointRules;
import org.opentmf.security.config.OptionsAccessDeniedHandler;
import org.opentmf.security.config.ServletErrorRenderer;
import org.opentmf.security.config.ServletHttpStatusMatrixFilter;
import org.opentmf.security.config.ServletJwtAutoConfiguration;
import org.opentmf.security.config.ServletJwtSupport;
import org.opentmf.security.config.ServletSupportedMethodsResolver;
import org.opentmf.security.config.SupportedMethodsWarmer;
import org.opentmf.security.jwks.ServletKeyOutageFilter;
import org.opentmf.security.model.OpenTmfSecurityProperties;
import org.opentmf.security.model.OpenTmfSecurityProperties.Management;
import org.opentmf.security.model.OtherEndpoints;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.boot.web.server.context.WebServerInitializedEvent;
import org.springframework.context.ApplicationContext;
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
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.HandlerMapping;

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
   * What the management server's {@link WebServerInitializedEvent} carried: the port and the
   * child context arrive together in it, and storing them as one reference makes "port matched
   * but context missing" unrepresentable, rather than a write-ordering rule a future edit could
   * break. The port is copied out once — the matcher runs for every request on every port, and
   * should compare an {@code int}, not re-derive it from the web server each time.
   */
  private record ManagementServer(int port, ApplicationContext context) {}

  private final AtomicReference<ManagementServer> managementServer = new AtomicReference<>();

  @EventListener
  void captureManagementPort(WebServerInitializedEvent event) {
    if (MANAGEMENT_SERVER_NAMESPACE.equals(event.getApplicationContext().getServerNamespace())) {
      managementServer.set(
          new ManagementServer(event.getWebServer().getPort(), event.getApplicationContext()));
    }
  }

  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  SecurityFilterChain managementSecurityFilterChain(HttpSecurity http) {
    log.info("Registering JWT-authenticated SecurityFilterChain for the management port.");
    var resolver = new ServletSupportedMethodsResolver(this::managementHandlerMappings);
    warmer.register(resolver::warmUp);
    return http
        .securityMatcher(this::isManagementPortRequest)
        .sessionManagement(session -> session.sessionCreationPolicy(STATELESS))
        .csrf(CsrfConfigurer::disable)
        .formLogin(FormLoginConfigurer::disable)
        .httpBasic(HttpBasicConfigurer::disable)
        .logout(LogoutConfigurer::disable)
        // The same HTTP-status matrix as the main port, answered from the management context.
        .addFilterBefore(
            new ServletHttpStatusMatrixFilter(resolver, this::managementExceptionResolvers),
            BearerTokenAuthenticationFilter.class)
        .addFilterBefore(
            new ServletKeyOutageFilter(
                new ServletErrorRenderer(this::managementExceptionResolvers)),
            BearerTokenAuthenticationFilter.class)
        .authorizeHttpRequests(this::applyManagementAuthorization)
        .exceptionHandling(handling -> configureDeniedHandler(handling, resolver))
        .oauth2ResourceServer(this::configureResourceServer)
        .build();
  }

  private boolean isManagementPortRequest(HttpServletRequest request) {
    ManagementServer server = managementServer.get();
    return server != null && request.getLocalPort() == server.port();
  }

  private void configureResourceServer(OAuth2ResourceServerConfigurer<HttpSecurity> oauth2) {
    servletJwtSupport.apply(oauth2);
  }

  /**
   * Installs the RFC 6750 denied-request handler on the {@code exceptionHandling} slot, which
   * covers every authorization denial on this port however the caller authenticated, so that
   * every {@code 403} here takes the same shape (status plus {@code WWW-Authenticate}, empty
   * body) rather than the framework's default error page for a non-bearer caller — decorated so
   * that an authenticated plain {@code OPTIONS} gets Spring's own answer, as on the main port.
   */
  private static void configureDeniedHandler(
      ExceptionHandlingConfigurer<HttpSecurity> handling,
      ServletSupportedMethodsResolver resolver) {
    handling.accessDeniedHandler(
        new OptionsAccessDeniedHandler(new BearerTokenAccessDeniedHandler(), resolver));
  }

  private final SupportedMethodsWarmer warmer = new SupportedMethodsWarmer();

  /** Warms this chain's resolver off the request path; see {@link SupportedMethodsWarmer}. */
  @Bean
  SupportedMethodsWarmer managementSupportedMethodsWarmer() {
    return warmer;
  }

  /**
   * The handler mappings of the management child context — the one that actually dispatches
   * management-port requests. This chain lives in the main context (see the class javadoc), so
   * the main context's own mappings are the wrong ones to consult: they describe the business
   * API, not the actuator, and answering a management-port request from them would serve, or
   * answer {@code 405} for, routes that port does not have. The child context is captured from
   * the same {@link WebServerInitializedEvent} the port comes from, and read only on first use,
   * long after that event.
   */
  private Stream<HandlerMapping> managementHandlerMappings() {
    // getBeansOfType, not getBeanProvider().stream(): the latter walks into ancestor contexts
    // and excludes a parent bean only when the child happens to define one under the same name.
    // It is also exactly what Boot's child dispatcher consults — its composite mapping
    // collects the child's own HandlerMapping beans the same way.
    return managementContext().getBeansOfType(HandlerMapping.class).values().stream();
  }

  /**
   * The exception resolvers the child dispatcher renders through: Boot's composite, which
   * itself walks up to the main context's resolvers, so the application's own error rendering
   * answers on this port too.
   */
  private Stream<HandlerExceptionResolver> managementExceptionResolvers() {
    return managementContext().getBeansOfType(HandlerExceptionResolver.class).values().stream();
  }

  private ApplicationContext managementContext() {
    ManagementServer server = managementServer.get();
    if (server == null) {
      // Not ready yet. Throwing rather than returning an empty context matters: the lookups
      // cache their first success and SingletonSupplier caches successes but not failures, so
      // an empty snapshot taken during startup would disable this port's matrix for the life
      // of the process. A throw costs one request and is retried.
      throw new IllegalStateException("The management context has not been initialized yet.");
    }
    return server.context();
  }

  private void applyManagementAuthorization(
      AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry
          requests) {
    Management management = properties.getManagement();
    management.getBlacklist().forEach(path -> requests.requestMatchers(path).denyAll());
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
