package org.opentmf.security.config;

import static org.opentmf.security.config.UniqueBeanResolver.resolveUnique;
import static org.springframework.security.config.Customizer.withDefaults;

import java.util.List;
import lombok.RequiredArgsConstructor;
import org.opentmf.security.model.OpenTmfSecurityProperties;
import org.opentmf.security.model.OtherEndpoints;
import org.opentmf.security.model.UnmatchedMethodResponse;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
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
import org.springframework.security.oauth2.server.resource.web.access.server.BearerTokenServerAccessDeniedHandler;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.security.web.server.savedrequest.NoOpServerRequestCache;
import org.springframework.util.CollectionUtils;
import org.springframework.web.reactive.result.method.RequestMappingInfoHandlerMapping;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;

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
  private final ObjectProvider<RequestMappingInfoHandlerMapping> handlerMappings;

  @Bean
  SecurityWebFilterChain reactiveSecurityFilterChain(ServerHttpSecurity http) {
    var entryPoint = resolveUnique(authenticationEntryPoints, ServerAuthenticationEntryPoint.class);
    var accessDeniedHandler = resolveUnique(accessDeniedHandlers, ServerAccessDeniedHandler.class);
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
            configureExceptionHandling(handling, entryPoint, accessDeniedHandler))
        .oauth2ResourceServer(configureResourceServer(entryPoint, accessDeniedHandler))
        .build();
  }

  /**
   * Applies the consumer-supplied handlers on the {@code ExceptionTranslationWebFilter} path: an
   * anonymous request hitting a protected URL (401) and authorization denials for authenticated
   * users (403). Leaving a handler unset keeps that path on the Spring Security default.
   */
  private void configureExceptionHandling(
      ExceptionHandlingSpec handling,
      ServerAuthenticationEntryPoint entryPoint,
      ServerAccessDeniedHandler accessDeniedHandler) {
    if (entryPoint != null) {
      handling.authenticationEntryPoint(entryPoint);
    }
    if (accessDeniedHandler != null) {
      handling.accessDeniedHandler(methodAware(accessDeniedHandler));
    }
  }

  /**
   * Decorates a denied-request handler so that a request for a method the application does not
   * serve on that path is answered {@code 405} rather than {@code 403}. Returns the handler
   * untouched when {@code opentmf.security.unmatched-method-response} is {@code DENY}.
   */
  private ServerAccessDeniedHandler methodAware(ServerAccessDeniedHandler delegate) {
    if (openTmfSecurityProperties.getUnmatchedMethodResponse()
        != UnmatchedMethodResponse.METHOD_NOT_ALLOWED) {
      return delegate;
    }
    List<PathPattern> blacklist = openTmfSecurityProperties.getBlacklist().stream()
        .map(PathPatternParser.defaultInstance::parse)
        .toList();
    return new MethodNotAllowedServerAccessDeniedHandler(
        delegate, new ReactiveSupportedMethodsResolver(handlerMappings::stream), blacklist);
  }

  /**
   * Besides the JWT wiring — one decoder, or an issuer-selecting resolver when
   * {@code opentmf.security.issuers} is configured — applies the consumer-supplied handlers on
   * the bearer-token path: invalid / expired / malformed tokens (401) and insufficient-scope
   * denials (403), which the bearer {@code AuthenticationWebFilter} handles before the
   * {@code ExceptionTranslationWebFilter} ever sees them.
   */
  private Customizer<OAuth2ResourceServerSpec> configureResourceServer(
      ServerAuthenticationEntryPoint entryPoint, ServerAccessDeniedHandler accessDeniedHandler) {
    return resourceServer -> {
      reactiveJwtSupport.apply(resourceServer);
      if (entryPoint != null) {
        resourceServer.authenticationEntryPoint(entryPoint);
      }
      configureDeniedHandler(resourceServer, accessDeniedHandler);
    };
  }

  /**
   * Sets the denied-request handler on the bearer-token path. Spring routes every denial of a
   * request carrying a bearer token here rather than to the global handler, so the {@code 405}
   * decoration has to be applied on this path too — every authenticated caller of this library
   * carries one. When there is nothing to decorate and no consumer handler, the slot is left
   * alone so Spring's own default keeps applying.
   */
  private void configureDeniedHandler(
      OAuth2ResourceServerSpec resourceServer, ServerAccessDeniedHandler consumerHandler) {
    boolean answersMethodNotAllowed = openTmfSecurityProperties.getUnmatchedMethodResponse()
        == UnmatchedMethodResponse.METHOD_NOT_ALLOWED;
    if (!answersMethodNotAllowed) {
      if (consumerHandler != null) {
        resourceServer.accessDeniedHandler(consumerHandler);
      }
      return;
    }
    ServerAccessDeniedHandler delegate = (consumerHandler != null)
        ? consumerHandler
        : new BearerTokenServerAccessDeniedHandler();
    resourceServer.accessDeniedHandler(methodAware(delegate));
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
