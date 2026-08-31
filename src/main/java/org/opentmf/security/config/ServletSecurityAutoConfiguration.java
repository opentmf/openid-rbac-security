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
import org.springframework.security.authorization.SingleResultAuthorizationManager;
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
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
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
        .oauth2ResourceServer(oauth2 -> configureResourceServer(oauth2, entryPoint))
        .build();
  }

  /**
   * The denied-request handler for one chain, decided once and installed on the
   * {@code exceptionHandling} slot, which covers every authorization denial regardless of how
   * the caller authenticated. Decorating only the resource server's bearer-token slot would
   * leave a denial of an authenticated-but-non-bearer caller — an application adding its own
   * pre-authentication mechanism beside this library — on the undecorated default, so the
   * documented 405 behavior would silently depend on how the request authenticated.
   *
   * <p>Without a consumer-supplied handler the delegate is the same
   * {@link BearerTokenAccessDeniedHandler} Spring's resource server would have installed for
   * bearer callers, so their denials answer exactly as before; the change is that every other
   * authenticated denial now goes through the same handler instead of the framework's default
   * error page.
   */
  private final class DeniedHandlers {

    private final AccessDeniedHandler global;

    private DeniedHandlers(AccessDeniedHandler consumerHandler) {
      boolean methodAware = openTmfSecurityProperties.getUnmatchedMethodResponse()
          == UnmatchedMethodResponse.METHOD_NOT_ALLOWED;
      if (!methodAware) {
        this.global = consumerHandler;
        return;
      }
      AccessDeniedHandler delegate = (consumerHandler != null)
          ? consumerHandler
          : new BearerTokenAccessDeniedHandler();
      this.global = new MethodNotAllowedAccessDeniedHandler(
          delegate,
          new ServletSupportedMethodsResolver(ServletSecurityAutoConfiguration.this::mappings));
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
      // Spring's own constant-result manager, denying with the recognisable BlacklistDecision,
      // which AuthorizationFilter carries to the denied-request handler inside the thrown
      // exception. See BlacklistDecision for why the type matters.
      var blacklistDenial =
          new SingleResultAuthorizationManager<RequestAuthorizationContext>(
              BlacklistDecision.INSTANCE);
      openTmfSecurityProperties.getBlacklist().forEach(blackListedEndpoint ->
          requests.requestMatchers(blackListedEndpoint).access(blacklistDenial));
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
   * {@code opentmf.security.issuers} is configured — applies the consumer-supplied entry point
   * on the bearer-token path: invalid / expired / malformed tokens (401), which the
   * {@code BearerTokenAuthenticationFilter} handles before the {@code ExceptionTranslationFilter}
   * ever sees them. Denials are not configured here: the denied-request handler lives on the
   * {@code exceptionHandling} slot, which covers this path too — see {@link DeniedHandlers}.
   */
  private void configureResourceServer(
      OAuth2ResourceServerConfigurer<HttpSecurity> oauth2, AuthenticationEntryPoint entryPoint) {
    servletJwtSupport.apply(oauth2);
    if (entryPoint != null) {
      oauth2.authenticationEntryPoint(entryPoint);
    }
  }

}
