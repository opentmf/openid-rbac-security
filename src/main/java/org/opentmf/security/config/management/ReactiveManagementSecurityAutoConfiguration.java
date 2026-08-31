package org.opentmf.security.config.management;

import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.opentmf.security.config.EndpointRules;
import org.opentmf.security.config.MethodNotAllowedServerAccessDeniedHandler;
import org.opentmf.security.config.ReactiveBlacklistDenial;
import org.opentmf.security.config.ReactiveJwtSupport;
import org.opentmf.security.config.ReactiveSupportedMethodsResolver;
import org.opentmf.security.model.OpenTmfSecurityProperties;
import org.opentmf.security.model.OpenTmfSecurityProperties.Management;
import org.opentmf.security.model.OtherEndpoints;
import org.opentmf.security.model.UnmatchedMethodResponse;
import org.springframework.boot.actuate.autoconfigure.web.ManagementContextConfiguration;
import org.springframework.boot.actuate.autoconfigure.web.ManagementContextType;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.boot.web.server.context.WebServerInitializedEvent;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.event.EventListener;
import org.springframework.context.annotation.Conditional;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity.AuthorizeExchangeSpec;
import org.springframework.security.config.web.server.ServerHttpSecurity.CsrfSpec;
import org.springframework.security.config.web.server.ServerHttpSecurity.ExceptionHandlingSpec;
import org.springframework.security.config.web.server.ServerHttpSecurity.FormLoginSpec;
import org.springframework.security.config.web.server.ServerHttpSecurity.HttpBasicSpec;
import org.springframework.security.config.web.server.ServerHttpSecurity.LogoutSpec;
import org.springframework.security.config.web.server.ServerHttpSecurity.OAuth2ResourceServerSpec;
import org.springframework.security.oauth2.server.resource.web.access.server.BearerTokenServerAccessDeniedHandler;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.security.web.server.savedrequest.NoOpServerRequestCache;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.web.reactive.result.method.RequestMappingInfoHandlerMapping;

/**
 * Registers a JWT-authenticated {@link SecurityWebFilterChain} into the management child
 * {@code ApplicationContext} when {@code management.server.port} differs from
 * {@code server.port}. Reuses the parent context's {@link ReactiveJwtSupport} so decoders,
 * claim mapping and multi-issuer routing are identical to the main port and cannot drift.
 *
 * <p>{@link OpenTmfSecurityProperties} and {@link ReactiveJwtSupport} are resolved from
 * the parent (root) context via Spring's parent-first bean lookup. IntelliJ's Spring
 * plugin does not model that for {@link ManagementContextConfiguration} classes, so the
 * suppression below silences spurious "no bean found" inspection warnings on the
 * constructor parameters.
 *
 * @author Gokhan Demir
 */
@ManagementContextConfiguration(ManagementContextType.CHILD)
@Conditional(OnSeparateManagementPortCondition.class)
@ConditionalOnClass({SecurityWebFilterChain.class, ServerHttpSecurity.class})
@ConditionalOnWebApplication(type = Type.REACTIVE)
@EnableWebFluxSecurity
@RequiredArgsConstructor
@SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection")
@Slf4j
public class ReactiveManagementSecurityAutoConfiguration {

  private final OpenTmfSecurityProperties properties;
  private final ReactiveJwtSupport reactiveJwtSupport;
  private final ApplicationContext applicationContext;

  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  SecurityWebFilterChain managementSecurityWebFilterChain(ServerHttpSecurity http) {
    log.info("Registering JWT-authenticated SecurityWebFilterChain for the management port.");
    return http
        .securityMatcher(ServerWebExchangeMatchers.pathMatchers("/**"))
        .requestCache(cache -> cache.requestCache(NoOpServerRequestCache.getInstance()))
        .csrf(CsrfSpec::disable)
        .formLogin(FormLoginSpec::disable)
        .httpBasic(HttpBasicSpec::disable)
        .logout(LogoutSpec::disable)
        .authorizeExchange(this::applyManagementAuthorization)
        .exceptionHandling(this::configureDeniedHandler)
        .oauth2ResourceServer(this::configureResourceServer)
        .build();
  }

  private void configureResourceServer(OAuth2ResourceServerSpec resourceServer) {
    reactiveJwtSupport.apply(resourceServer);
  }

  /**
   * Installs the denied-request handler on the {@code exceptionHandling} slot — which covers
   * every authorization denial on this port, however the caller authenticated — so that a
   * request for a method the actuator does not serve on that path is answered {@code 405}
   * rather than {@code 403}, honouring the management section's own
   * {@code unmatched-method-response}.
   */
  private void configureDeniedHandler(ExceptionHandlingSpec handling) {
    if (properties.getManagement().getUnmatchedMethodResponse()
        == UnmatchedMethodResponse.METHOD_NOT_ALLOWED) {
      var resolver = new ReactiveSupportedMethodsResolver(this::managementHandlerMappings);
      methodsResolver.set(resolver);
      handling.accessDeniedHandler(new MethodNotAllowedServerAccessDeniedHandler(
          new BearerTokenServerAccessDeniedHandler(), resolver));
    }
  }

  /** The chain's resolver, kept so {@link #warmUpSupportedMethods} can prime it at startup. */
  private final AtomicReference<ReactiveSupportedMethodsResolver> methodsResolver =
      new AtomicReference<>();

  /**
   * Takes the resolver's lazy handler-mapping lookup off the first denial's back — which would
   * land on a Netty event-loop thread. This configuration lives in the management child
   * context, which never sees the main application's {@code ApplicationReadyEvent}; the child's
   * own {@code WebServerInitializedEvent} is the moment its mappings exist and its server is
   * about to take traffic.
   */
  @EventListener
  void warmUpSupportedMethods(WebServerInitializedEvent event) {
    ReactiveSupportedMethodsResolver resolver = methodsResolver.get();
    if (resolver != null
        && "management".equals(event.getApplicationContext().getServerNamespace())) {
      resolver.warmUp();
    }
  }

  /**
   * The management child context's own handler mappings — the actuator's. {@code getBeansOfType}
   * rather than {@code getBeanProvider().stream()}, because the latter walks into the parent
   * context and excludes a parent bean only when this one defines another under the same name;
   * a differently named mapping in the main context would otherwise let this port advertise the
   * business API's verbs.
   */
  private Stream<RequestMappingInfoHandlerMapping> managementHandlerMappings() {
    return applicationContext.getBeansOfType(RequestMappingInfoHandlerMapping.class)
        .values()
        .stream();
  }

  private void applyManagementAuthorization(AuthorizeExchangeSpec exchanges) {
    Management management = properties.getManagement();
    var blacklistDenial = new ReactiveBlacklistDenial();
    management.getBlacklist().forEach(path ->
        exchanges.pathMatchers(path).access(blacklistDenial));
    management.getWhitelist().forEach(path -> exchanges.pathMatchers(path).permitAll());
    management.getAllowedEndpoints().forEach(endpoint -> {
      for (HttpMethod method : EndpointRules.httpMethodsFor(endpoint)) {
        exchanges.pathMatchers(method, endpoint.getPath()).permitAll();
      }
    });
    management.getSecureEndpoints().forEach(endpoint -> {
      for (HttpMethod method : EndpointRules.httpMethodsFor(endpoint)) {
        exchanges.pathMatchers(method, endpoint.getPath()).hasAnyAuthority(endpoint.getRoles());
      }
    });
    OtherEndpoints policy = management.getOtherEndpoints();
    switch (policy) {
      case ALLOW -> exchanges.anyExchange().permitAll();
      case DENY -> exchanges.anyExchange().denyAll();
      case AUTHENTICATED -> exchanges.anyExchange().authenticated();
    }
  }
}
