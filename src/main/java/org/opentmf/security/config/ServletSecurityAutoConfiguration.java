package org.opentmf.security.config;

import static org.opentmf.security.config.UniqueBeanResolver.resolveUnique;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

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
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.config.annotation.web.configurers.HttpBasicConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.CollectionUtils;
import org.springframework.web.servlet.mvc.method.RequestMappingInfoHandlerMapping;

/**
 * OpenTMF Web Security configures according to the supplied OpenTmfSecurityProperties.
 *
 * @author Gokhan Demir
 */
@AutoConfiguration(after = ServletJwtAutoConfiguration.class)
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true, jsr250Enabled = true)
@EnableConfigurationProperties(OpenTmfSecurityProperties.class)
@RequiredArgsConstructor
@ConditionalOnWebApplication(type = Type.SERVLET)
public class ServletSecurityAutoConfiguration {

  private final OpenTmfSecurityProperties openTmfSecurityProperties;
  private final ServletJwtSupport servletJwtSupport;
  private final ObjectProvider<AuthenticationEntryPoint> authenticationEntryPoints;
  private final ObjectProvider<AccessDeniedHandler> accessDeniedHandlers;
  private final ObjectProvider<RequestMappingInfoHandlerMapping> handlerMappings;
  private final ObjectProvider<PathPatternRequestMatcher.Builder> requestMatcherBuilders;

  @Bean
  SecurityFilterChain servletSecurityFilterChain(HttpSecurity http) {
    var entryPoint = resolveUnique(authenticationEntryPoints, AuthenticationEntryPoint.class);
    var accessDeniedHandler = resolveUnique(accessDeniedHandlers, AccessDeniedHandler.class);
    return http
        .sessionManagement(session -> session.sessionCreationPolicy(STATELESS))
        .csrf(CsrfConfigurer::disable)
        .formLogin(FormLoginConfigurer::disable)
        .httpBasic(HttpBasicConfigurer::disable)
        .logout(LogoutConfigurer::disable)
        .headers(withDefaults())
        .cors(withDefaults())
        .authorizeHttpRequests(this::applyOpenTmfSecurityDefinitions)
        .exceptionHandling(handling ->
            configureExceptionHandling(handling, entryPoint, accessDeniedHandler))
        .oauth2ResourceServer(oauth2 ->
            configureResourceServer(oauth2, entryPoint, accessDeniedHandler))
        .build();
  }

  /**
   * Applies the consumer-supplied handlers on the {@code ExceptionTranslationFilter} path: an
   * anonymous request hitting a protected URL (401) and authorization denials for authenticated
   * users (403). Leaving a handler unset keeps that path on the Spring Security default.
   */
  private void configureExceptionHandling(
      ExceptionHandlingConfigurer<HttpSecurity> handling,
      AuthenticationEntryPoint entryPoint,
      AccessDeniedHandler accessDeniedHandler) {
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
  private AccessDeniedHandler methodAware(AccessDeniedHandler delegate) {
    if (openTmfSecurityProperties.getUnmatchedMethodResponse()
        != UnmatchedMethodResponse.METHOD_NOT_ALLOWED) {
      return delegate;
    }
    PathPatternRequestMatcher.Builder builder =
        requestMatcherBuilders.getIfAvailable(PathPatternRequestMatcher::withDefaults);
    List<RequestMatcher> blacklist = openTmfSecurityProperties.getBlacklist().stream()
        .map(path -> (RequestMatcher) builder.matcher(path))
        .toList();
    return new MethodNotAllowedAccessDeniedHandler(
        delegate, new ServletSupportedMethodsResolver(handlerMappings::stream), blacklist);
  }

  private void applyOpenTmfSecurityDefinitions(
      AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry requests) {
    configureBlacklist(requests);
    configureWhitelist(requests);
    configureAllowedEndpoints(requests);
    configureSecureEndpoints(requests);
    configureOtherEndpoints(requests);
  }

  private void configureOtherEndpoints(
      AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry requests) {
    OtherEndpoints policy = openTmfSecurityProperties.getOtherEndpoints();
    switch (policy) {
      case ALLOW -> requests.anyRequest().permitAll();
      case DENY -> requests.anyRequest().denyAll();
      case AUTHENTICATED -> requests.anyRequest().authenticated();
    }
  }

  private void configureWhitelist(
      AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry requests) {
    if (!CollectionUtils.isEmpty(openTmfSecurityProperties.getWhitelist())) {
      openTmfSecurityProperties.getWhitelist()
          .forEach(whiteListedEndpoint -> requests.requestMatchers(whiteListedEndpoint).permitAll());
    }
  }

  private void configureBlacklist(
      AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry requests) {
    if (!CollectionUtils.isEmpty(openTmfSecurityProperties.getBlacklist())) {
      openTmfSecurityProperties.getBlacklist()
          .forEach(blackListedEndpoint -> requests.requestMatchers(blackListedEndpoint).denyAll());
    }
  }

  private void configureAllowedEndpoints(
      AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry requests) {
    openTmfSecurityProperties.getAllowedEndpoints().forEach(endpoint -> {
      for (HttpMethod method : EndpointRules.httpMethodsFor(endpoint)) {
        requests.requestMatchers(method, endpoint.getPath()).permitAll();
      }
    });
  }

  private void configureSecureEndpoints(
      AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry requests) {
    openTmfSecurityProperties.getSecureEndpoints().forEach(endpoint -> {
      for (HttpMethod method : EndpointRules.httpMethodsFor(endpoint)) {
        requests.requestMatchers(method, endpoint.getPath()).hasAnyAuthority(endpoint.getRoles());
      }
    });
  }

  /**
   * Besides the JWT wiring — one decoder, or an issuer-selecting resolver when
   * {@code opentmf.security.issuers} is configured — applies the consumer-supplied handlers on
   * the bearer-token path: invalid / expired / malformed tokens (401) and insufficient-scope
   * denials (403), which the {@code BearerTokenAuthenticationFilter} handles before the
   * {@code ExceptionTranslationFilter} ever sees them.
   */
  private void configureResourceServer(
      OAuth2ResourceServerConfigurer<HttpSecurity> oauth2,
      AuthenticationEntryPoint entryPoint,
      AccessDeniedHandler accessDeniedHandler) {
    servletJwtSupport.apply(oauth2);
    if (entryPoint != null) {
      oauth2.authenticationEntryPoint(entryPoint);
    }
    configureDeniedHandler(oauth2, accessDeniedHandler);
  }

  /**
   * Sets the denied-request handler on the bearer-token path. Spring routes every denial of a
   * request carrying a bearer token here rather than to the global handler, so the {@code 405}
   * decoration has to be applied on this path too — every authenticated caller of this library
   * carries one. When there is nothing to decorate and no consumer handler, the slot is left
   * alone so Spring's own default keeps applying.
   */
  private void configureDeniedHandler(
      OAuth2ResourceServerConfigurer<HttpSecurity> oauth2, AccessDeniedHandler consumerHandler) {
    boolean answersMethodNotAllowed = openTmfSecurityProperties.getUnmatchedMethodResponse()
        == UnmatchedMethodResponse.METHOD_NOT_ALLOWED;
    if (!answersMethodNotAllowed) {
      if (consumerHandler != null) {
        oauth2.accessDeniedHandler(consumerHandler);
      }
      return;
    }
    AccessDeniedHandler delegate =
        (consumerHandler != null) ? consumerHandler : new BearerTokenAccessDeniedHandler();
    oauth2.accessDeniedHandler(methodAware(delegate));
  }
}
