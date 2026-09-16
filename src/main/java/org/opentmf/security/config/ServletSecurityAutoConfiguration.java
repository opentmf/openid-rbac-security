package org.opentmf.security.config;

import static org.opentmf.security.config.UniqueBeanResolver.resolveUnique;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

import java.util.stream.Stream;
import lombok.RequiredArgsConstructor;
import org.opentmf.security.jwks.ServletKeyOutageFilter;
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
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.StrictHttpFirewall;
import org.springframework.util.CollectionUtils;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.HandlerMapping;

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

  private final SupportedMethodsWarmer warmer = new SupportedMethodsWarmer();

  /** Warms this chain's resolver off the request path; see {@link SupportedMethodsWarmer}. */
  @Bean
  SupportedMethodsWarmer servletSupportedMethodsWarmer() {
    return warmer;
  }

  /**
   * Lets every HTTP method name into the chain, so that an unknown one ({@code PROPFIND},
   * {@code BREW}) reaches the status matrix and is answered {@code 404} or {@code 405} like any
   * other method, instead of being rejected as {@code 400} by the firewall before any filter
   * runs. Everything else the strict firewall guards — path traversal, encoded separators,
   * malformed headers — is left exactly as it is. A consumer's own {@link HttpFirewall} bean
   * takes precedence, and then unknown method names keep whatever answer that firewall gives.
   */
  @Bean
  @ConditionalOnMissingBean(HttpFirewall.class)
  HttpFirewall anyMethodNameHttpFirewall() {
    var firewall = new StrictHttpFirewall();
    firewall.setUnsafeAllowAnyHttpMethod(true);
    return firewall;
  }

  @Bean
  SecurityFilterChain servletSecurityFilterChain(HttpSecurity http) {
    var entryPoint = resolveUnique(authenticationEntryPoints, AuthenticationEntryPoint.class);
    var accessDeniedHandler = resolveUnique(accessDeniedHandlers, AccessDeniedHandler.class);
    var resolver = new ServletSupportedMethodsResolver(this::handlerMappings);
    warmer.register(resolver::warmUp);
    return http
        .sessionManagement(session -> session.sessionCreationPolicy(STATELESS))
        .csrf(CsrfConfigurer::disable)
        .formLogin(FormLoginConfigurer::disable)
        .httpBasic(HttpBasicConfigurer::disable)
        .logout(LogoutConfigurer::disable)
        .headers(withDefaults())
        .cors(withDefaults())
        // Before authentication: an unknown path is 404 and an unimplemented method 405 for
        // every caller, token or no token, valid or not — the access rules see the rest.
        .addFilterBefore(
            new ServletHttpStatusMatrixFilter(resolver, this::exceptionResolvers),
            BearerTokenAuthenticationFilter.class)
        // Around the bearer filter: an issuer whose keys are unavailable answers the typed 503.
        .addFilterBefore(
            new ServletKeyOutageFilter(new ServletErrorRenderer(this::exceptionResolvers)),
            BearerTokenAuthenticationFilter.class)
        .authorizeHttpRequests(this::applyOpenTmfSecurityDefinitions)
        .exceptionHandling(handling ->
            configureExceptionHandling(handling, entryPoint, accessDeniedHandler, resolver))
        .oauth2ResourceServer(oauth2 -> configureResourceServer(oauth2, entryPoint))
        .build();
  }

  /**
   * The handler mappings this context's {@code DispatcherServlet} dispatches with — which, for
   * the main context, includes a parent context's, exactly as the dispatcher's own detection
   * does.
   */
  private Stream<HandlerMapping> handlerMappings() {
    return BeanFactoryUtils.beansOfTypeIncludingAncestors(applicationContext, HandlerMapping.class)
        .values()
        .stream();
  }

  /** The exception resolvers the same dispatcher renders through; detected the same way. */
  private Stream<HandlerExceptionResolver> exceptionResolvers() {
    return BeanFactoryUtils
        .beansOfTypeIncludingAncestors(applicationContext, HandlerExceptionResolver.class)
        .values()
        .stream();
  }

  /**
   * Applies the handlers on the {@code ExceptionTranslationFilter} path: an anonymous request
   * hitting a protected URL (401) and authorization denials for authenticated users (403).
   * Leaving the entry point unset keeps that path on the Spring Security default. The denied
   * handler is always set, on this slot, which covers every authorization denial regardless of
   * how the caller authenticated: without a consumer-supplied handler it is the same
   * {@link BearerTokenAccessDeniedHandler} Spring's resource server would have installed for
   * bearer callers, so their denials answer exactly as before, and an authenticated-but-non-bearer
   * caller — an application adding its own pre-authentication beside this library — gets the
   * same RFC 6750 shape rather than the framework's default error page. Either handler is
   * decorated so that an authenticated plain {@code OPTIONS} gets Spring's own answer — see
   * {@link OptionsAccessDeniedHandler}.
   */
  private static void configureExceptionHandling(
      ExceptionHandlingConfigurer<HttpSecurity> handling,
      AuthenticationEntryPoint entryPoint,
      AccessDeniedHandler consumerHandler,
      ServletSupportedMethodsResolver resolver) {
    if (entryPoint != null) {
      handling.authenticationEntryPoint(entryPoint);
    }
    AccessDeniedHandler delegate =
        consumerHandler != null ? consumerHandler : new BearerTokenAccessDeniedHandler();
    handling.accessDeniedHandler(new OptionsAccessDeniedHandler(delegate, resolver));
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
   * {@code opentmf.security.issuers} is configured — applies the consumer-supplied entry point
   * on the bearer-token path: invalid / expired / malformed tokens (401), which the
   * {@code BearerTokenAuthenticationFilter} handles before the {@code ExceptionTranslationFilter}
   * ever sees them. Denials are not configured here: the denied-request handler lives on the
   * {@code exceptionHandling} slot, which covers this path too — see
   * {@link #configureExceptionHandling}.
   */
  private void configureResourceServer(
      OAuth2ResourceServerConfigurer<HttpSecurity> oauth2, AuthenticationEntryPoint entryPoint) {
    servletJwtSupport.apply(oauth2);
    if (entryPoint != null) {
      oauth2.authenticationEntryPoint(entryPoint);
    }
  }

}
