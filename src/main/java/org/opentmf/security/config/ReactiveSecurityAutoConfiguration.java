package org.opentmf.security.config;

import static org.opentmf.security.config.UniqueBeanResolver.resolveUnique;
import static org.springframework.security.config.Customizer.withDefaults;

import java.util.stream.Stream;
import lombok.RequiredArgsConstructor;
import org.opentmf.security.jwks.ReactiveKeyOutageFilter;
import org.opentmf.security.model.OpenTmfSecurityProperties;
import org.opentmf.security.model.OtherEndpoints;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
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
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.oauth2.server.resource.web.access.server.BearerTokenServerAccessDeniedHandler;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.security.web.server.firewall.ServerWebExchangeFirewall;
import org.springframework.security.web.server.firewall.StrictServerWebExchangeFirewall;
import org.springframework.security.web.server.savedrequest.NoOpServerRequestCache;
import org.springframework.util.CollectionUtils;
import org.springframework.web.reactive.HandlerMapping;

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

  private final SupportedMethodsWarmer warmer = new SupportedMethodsWarmer();

  /** Warms this chain's resolver off the request path; see {@link SupportedMethodsWarmer}. */
  @Bean
  SupportedMethodsWarmer reactiveSupportedMethodsWarmer() {
    return warmer;
  }

  /**
   * Lets every HTTP method name into the chain, so that an unknown one ({@code PROPFIND},
   * {@code BREW}) reaches the status matrix and is answered {@code 404} or {@code 405} like any
   * other method, instead of being rejected as {@code 400} by the firewall before any filter
   * runs; the reactive twin of the servlet firewall bean, picked up by every
   * {@code WebFilterChainProxy} including the management port's. Everything else the strict
   * firewall guards is left as it is, and a consumer's own bean takes precedence.
   */
  @Bean
  @ConditionalOnMissingBean(ServerWebExchangeFirewall.class)
  ServerWebExchangeFirewall anyMethodNameServerWebExchangeFirewall() {
    var firewall = new StrictServerWebExchangeFirewall();
    firewall.setUnsafeAllowAnyHttpMethod(true);
    return firewall;
  }

  @Bean
  SecurityWebFilterChain reactiveSecurityFilterChain(ServerHttpSecurity http) {
    var entryPoint = resolveUnique(authenticationEntryPoints, ServerAuthenticationEntryPoint.class);
    var accessDeniedHandler = resolveUnique(accessDeniedHandlers, ServerAccessDeniedHandler.class);
    var resolver = new ReactiveSupportedMethodsResolver(this::handlerMappings);
    warmer.register(resolver::warmUp);
    return http
        .requestCache(cache -> cache.requestCache(NoOpServerRequestCache.getInstance()))
        .csrf(CsrfSpec::disable)
        .formLogin(FormLoginSpec::disable)
        .httpBasic(HttpBasicSpec::disable)
        .logout(LogoutSpec::disable)
        .headers(withDefaults())
        .cors(withDefaults())
        // Before authentication: an unknown path is 404 and an unimplemented method 405 for
        // every caller, token or no token, valid or not — the access rules see the rest.
        .addFilterBefore(
            new ReactiveHttpStatusMatrixFilter(resolver), SecurityWebFiltersOrder.AUTHENTICATION)
        // Around the bearer filter: an issuer whose keys are unavailable answers the typed 503.
        .addFilterBefore(new ReactiveKeyOutageFilter(), SecurityWebFiltersOrder.AUTHENTICATION)
        .authorizeExchange(applyOpenTmfSecurityDefinitions())
        .exceptionHandling(handling ->
            configureExceptionHandling(handling, entryPoint, accessDeniedHandler, resolver))
        .oauth2ResourceServer(configureResourceServer(entryPoint))
        .build();
  }

  /**
   * The handler mappings this context's {@code DispatcherHandler} dispatches with — which, for
   * the main context, includes a parent context's, exactly as the dispatcher's own detection
   * does.
   */
  private Stream<HandlerMapping> handlerMappings() {
    return BeanFactoryUtils.beansOfTypeIncludingAncestors(applicationContext, HandlerMapping.class)
        .values()
        .stream();
  }

  /**
   * Applies the handlers on the {@code ExceptionTranslationWebFilter} path: an anonymous request
   * hitting a protected URL (401) and authorization denials for authenticated users (403).
   * Leaving the entry point unset keeps that path on the Spring Security default; the denied
   * handler is always set and decorated for {@code OPTIONS}, for the reasons the servlet twin
   * gives.
   */
  private static void configureExceptionHandling(
      ExceptionHandlingSpec handling,
      ServerAuthenticationEntryPoint entryPoint,
      ServerAccessDeniedHandler consumerHandler,
      ReactiveSupportedMethodsResolver resolver) {
    if (entryPoint != null) {
      handling.authenticationEntryPoint(entryPoint);
    }
    ServerAccessDeniedHandler delegate =
        consumerHandler != null ? consumerHandler : new BearerTokenServerAccessDeniedHandler();
    handling.accessDeniedHandler(new OptionsServerAccessDeniedHandler(delegate, resolver));
  }

  /**
   * Besides the JWT wiring — one decoder, or an issuer-selecting resolver when
   * {@code opentmf.security.issuers} is configured — applies the consumer-supplied entry point
   * on the bearer-token path: invalid / expired / malformed tokens (401), which the bearer
   * {@code AuthenticationWebFilter} handles before the {@code ExceptionTranslationWebFilter}
   * ever sees them. Denials are not configured here: the denied-request handler lives on the
   * {@code exceptionHandling} slot, which covers this path too — see
   * {@link #configureExceptionHandling}.
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
          .denyAll();
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
