package org.opentmf.security.config;

import static org.opentmf.security.config.UniqueBeanResolver.resolveUnique;
import static org.springframework.security.config.Customizer.withDefaults;

import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
import lombok.RequiredArgsConstructor;
import org.opentmf.security.model.OpenTmfSecurityProperties;
import org.opentmf.security.model.OtherEndpoints;
import org.opentmf.security.model.UnmatchedMethodResponse;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.event.EventListener;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
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
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.security.web.server.savedrequest.NoOpServerRequestCache;
import org.springframework.util.CollectionUtils;
import org.springframework.web.reactive.result.method.RequestMappingInfoHandlerMapping;

/**
 * OpenTMF Reactive Security configures according to the supplied OpenTmfSecurityProperties.
 *
 * @author Gokhan Demir
 */
@AutoConfiguration(after = ReactiveJwtAutoConfiguration.class)
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
@EnableConfigurationProperties(OpenTmfSecurityProperties.class)
@RequiredArgsConstructor
@ConditionalOnWebApplication(type = Type.REACTIVE)
public class ReactiveSecurityAutoConfiguration {

  private final OpenTmfSecurityProperties openTmfSecurityProperties;
  private final ReactiveJwtSupport reactiveJwtSupport;
  private final ObjectProvider<ServerAuthenticationEntryPoint> authenticationEntryPoints;
  private final ObjectProvider<ServerAccessDeniedHandler> accessDeniedHandlers;
  private final ApplicationContext applicationContext;

  /** The chain's resolver, kept so {@link #warmUpSupportedMethods()} can prime it at startup. */
  private final AtomicReference<ReactiveSupportedMethodsResolver> methodsResolver =
      new AtomicReference<>();

  /**
   * Takes the resolver's lazy handler-mapping lookup off the first denial's back — which on
   * this stack would land on a Netty event-loop thread — once the application, and with it
   * every handler mapping, is ready. A failure here is harmless: the lookup is simply retried
   * on the first denial.
   */
  @EventListener(ApplicationReadyEvent.class)
  void warmUpSupportedMethods() {
    ReactiveSupportedMethodsResolver resolver = methodsResolver.get();
    if (resolver != null) {
      resolver.warmUp();
    }
  }

  @Bean
  SecurityWebFilterChain reactiveSecurityFilterChain(ServerHttpSecurity http) {
    var entryPoint = resolveUnique(authenticationEntryPoints, ServerAuthenticationEntryPoint.class);
    var accessDeniedHandler = resolveUnique(accessDeniedHandlers, ServerAccessDeniedHandler.class);
    var deniedHandlers = new DeniedHandlers(accessDeniedHandler);
    return http
        .requestCache(cache -> cache.requestCache(NoOpServerRequestCache.getInstance()))
        .csrf(CsrfSpec::disable)
        .formLogin(FormLoginSpec::disable)
        .httpBasic(HttpBasicSpec::disable)
        .logout(LogoutSpec::disable)
        .headers(withDefaults())
        .cors(withDefaults())
        .authorizeExchange(applyOpenTmfSecurityDefinitions())
        .exceptionHandling(handling ->
            configureExceptionHandling(handling, entryPoint, deniedHandlers))
        .oauth2ResourceServer(configureResourceServer(entryPoint))
        .build();
  }

  /**
   * The denied-request handler for one chain, decided once and installed on the
   * {@code exceptionHandling} slot, which covers every authorization denial regardless of how
   * the caller authenticated. See the servlet twin for why decorating only the bearer-token
   * slot would make the documented 405 behavior depend on how the request authenticated.
   */
  private final class DeniedHandlers {

    private final ServerAccessDeniedHandler global;

    private DeniedHandlers(ServerAccessDeniedHandler consumerHandler) {
      boolean methodAware = openTmfSecurityProperties.getUnmatchedMethodResponse()
          == UnmatchedMethodResponse.METHOD_NOT_ALLOWED;
      if (!methodAware) {
        this.global = consumerHandler;
        return;
      }
      ServerAccessDeniedHandler delegate = (consumerHandler != null)
          ? consumerHandler
          : new BearerTokenServerAccessDeniedHandler();
      var resolver =
          new ReactiveSupportedMethodsResolver(ReactiveSecurityAutoConfiguration.this::mappings);
      methodsResolver.set(resolver);
      this.global = new MethodNotAllowedServerAccessDeniedHandler(delegate, resolver);
    }
  }

  /**
   * The handler mappings of this context and no other. A lookup that reached into a parent
   * context would let this chain answer for routes it does not serve.
   */
  private Stream<RequestMappingInfoHandlerMapping> mappings() {
    return applicationContext.getBeansOfType(RequestMappingInfoHandlerMapping.class)
        .values()
        .stream();
  }

  /**
   * Applies the consumer-supplied handlers on the {@code ExceptionTranslationWebFilter} path: an
   * anonymous request hitting a protected URL (401) and authorization denials for authenticated
   * users (403). Leaving a handler unset keeps that path on the Spring Security default.
   */
  private void configureExceptionHandling(
      ExceptionHandlingSpec handling,
      ServerAuthenticationEntryPoint entryPoint,
      DeniedHandlers deniedHandlers) {
    if (entryPoint != null) {
      handling.authenticationEntryPoint(entryPoint);
    }
    if (deniedHandlers.global != null) {
      handling.accessDeniedHandler(deniedHandlers.global);
    }
  }

  /**
   * Besides the JWT wiring — one decoder, or an issuer-selecting resolver when
   * {@code opentmf.security.issuers} is configured — applies the consumer-supplied entry point
   * on the bearer-token path: invalid / expired / malformed tokens (401), which the bearer
   * {@code AuthenticationWebFilter} handles before the {@code ExceptionTranslationWebFilter}
   * ever sees them. Denials are not configured here: the denied-request handler lives on the
   * {@code exceptionHandling} slot, which covers this path too — see {@link DeniedHandlers}.
   */
  private Customizer<OAuth2ResourceServerSpec> configureResourceServer(
      ServerAuthenticationEntryPoint entryPoint) {
    return resourceServer -> {
      reactiveJwtSupport.apply(resourceServer);
      if (entryPoint != null) {
        resourceServer.authenticationEntryPoint(entryPoint);
      }
    };
  }

  private Customizer<AuthorizeExchangeSpec> applyOpenTmfSecurityDefinitions() {
    return exchanges -> {
      configureBlacklist(exchanges);
      configureWhiteList(exchanges);
      configureAllowedEndpoints(exchanges);
      configureSecureEndpoints(exchanges);
      configureOtherEndpoints(exchanges);
    };
  }

  private void configureOtherEndpoints(AuthorizeExchangeSpec exchanges) {
    OtherEndpoints policy = openTmfSecurityProperties.getOtherEndpoints();
    switch (policy) {
      case ALLOW -> exchanges.anyExchange().permitAll();
      case DENY -> exchanges.anyExchange().denyAll();
      case AUTHENTICATED -> exchanges.anyExchange().authenticated();
    }
  }

  private void configureAllowedEndpoints(AuthorizeExchangeSpec exchanges) {
    for (var allow : openTmfSecurityProperties.getAllowedEndpoints()) {
      for (HttpMethod method : EndpointRules.httpMethodsFor(allow)) {
        exchanges.pathMatchers(method, allow.getPath()).permitAll();
      }
    }
  }

  private void configureWhiteList(AuthorizeExchangeSpec exchanges) {
    if (!CollectionUtils.isEmpty(openTmfSecurityProperties.getWhitelist())) {
      exchanges.pathMatchers(openTmfSecurityProperties.getWhitelist().toArray(String[]::new))
          .permitAll();
    }
  }

  private void configureBlacklist(AuthorizeExchangeSpec exchanges) {
    if (!CollectionUtils.isEmpty(openTmfSecurityProperties.getBlacklist())) {
      exchanges.pathMatchers(openTmfSecurityProperties.getBlacklist().toArray(String[]::new))
          .access(new ReactiveBlacklistDenial());
    }
  }

  private void configureSecureEndpoints(AuthorizeExchangeSpec exchanges) {
    for (var restricted : openTmfSecurityProperties.getSecureEndpoints()) {
      for (HttpMethod method : EndpointRules.httpMethodsFor(restricted)) {
        exchanges.pathMatchers(method, restricted.getPath())
            .hasAnyAuthority(restricted.getRoles());
      }
    }
  }
}
