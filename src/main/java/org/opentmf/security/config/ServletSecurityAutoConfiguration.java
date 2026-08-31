package org.opentmf.security.config;

import static org.opentmf.security.config.UniqueBeanResolver.resolveUnique;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

import java.util.stream.Stream;
import lombok.RequiredArgsConstructor;
import org.opentmf.security.model.OpenTmfSecurityProperties;
import org.opentmf.security.model.OtherEndpoints;
import org.opentmf.security.model.UnmatchedMethodResponse;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
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
  private final ApplicationContext applicationContext;

  @Bean
  SecurityFilterChain servletSecurityFilterChain(HttpSecurity http) {
    var entryPoint = resolveUnique(authenticationEntryPoints, AuthenticationEntryPoint.class);
    var accessDeniedHandler = resolveUnique(accessDeniedHandlers, AccessDeniedHandler.class);
    var deniedHandlers = new DeniedHandlers(accessDeniedHandler);
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
            configureExceptionHandling(handling, entryPoint, deniedHandlers))
        .oauth2ResourceServer(oauth2 ->
            configureResourceServer(oauth2, entryPoint, deniedHandlers))
        .build();
  }

  /**
   * The denied-request handlers for one chain, decided once so that the two slots they are
   * installed into cannot end up with different objects — or with a second, unreachable copy.
   *
   * <p>Setting {@code exceptionHandling}'s handler makes it global: Spring then ignores the
   * resource server's per-matcher registration entirely. So exactly one slot is ever used. With
   * a consumer-supplied handler the global slot carries it; without one, only the bearer-token
   * slot needs the decoration, since every authenticated caller of this library carries a token.
   */
  private final class DeniedHandlers {

    private final ServletSupportedMethodsResolver resolver;
    private final AccessDeniedHandler global;
    private final AccessDeniedHandler bearer;

    private DeniedHandlers(AccessDeniedHandler consumerHandler) {
      boolean methodAware = openTmfSecurityProperties.getUnmatchedMethodResponse()
          == UnmatchedMethodResponse.METHOD_NOT_ALLOWED;
      this.resolver = methodAware
          ? new ServletSupportedMethodsResolver(ServletSecurityAutoConfiguration.this::mappings)
          : null;
      this.global = (consumerHandler != null) ? decorate(consumerHandler) : null;
      this.bearer = (consumerHandler != null || !methodAware)
          ? null
          : decorate(new BearerTokenAccessDeniedHandler());
    }

    private AccessDeniedHandler decorate(AccessDeniedHandler delegate) {
      return (resolver == null)
          ? delegate
          : new MethodNotAllowedAccessDeniedHandler(delegate, resolver);
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
   * Applies the consumer-supplied handlers on the {@code ExceptionTranslationFilter} path: an
   * anonymous request hitting a protected URL (401) and authorization denials for authenticated
   * users (403). Leaving a handler unset keeps that path on the Spring Security default.
   */
  private void configureExceptionHandling(
      ExceptionHandlingConfigurer<HttpSecurity> handling,
      AuthenticationEntryPoint entryPoint,
      DeniedHandlers deniedHandlers) {
    if (entryPoint != null) {
      handling.authenticationEntryPoint(entryPoint);
    }
    if (deniedHandlers.global != null) {
      handling.accessDeniedHandler(deniedHandlers.global);
    }
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
      openTmfSecurityProperties.getBlacklist().forEach(blackListedEndpoint ->
          requests.requestMatchers(blackListedEndpoint).access(ServletBlacklistDenial.INSTANCE));
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
      DeniedHandlers deniedHandlers) {
    servletJwtSupport.apply(oauth2);
    if (entryPoint != null) {
      oauth2.authenticationEntryPoint(entryPoint);
    }
    if (deniedHandlers.bearer != null) {
      oauth2.accessDeniedHandler(deniedHandlers.bearer);
    }
  }

}
