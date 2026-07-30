package org.opentmf.security.config;

import static org.opentmf.security.config.CommonConfig.authoritiesClaimName;
import static org.opentmf.security.config.CommonConfig.principalClaimName;
import static org.opentmf.security.config.UniqueBeanResolver.resolveUnique;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

import java.util.List;
import lombok.RequiredArgsConstructor;
import org.opentmf.security.jwt.GrantedAuthoritiesConverter;
import org.opentmf.security.jwt.ServletJwtPrincipalConverter;
import org.opentmf.security.model.OpenTmfSecurityProperties;
import org.opentmf.security.model.OtherEndpoints;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.HttpBasicConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.util.CollectionUtils;

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
  private final JwtDecoder jwtDecoder;
  private final ObjectProvider<AuthenticationEntryPoint> authenticationEntryPoints;
  private final ObjectProvider<AccessDeniedHandler> accessDeniedHandlers;

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
      handling.accessDeniedHandler(accessDeniedHandler);
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
      openTmfSecurityProperties.getBlacklist()
          .forEach(blackListedEndpoint -> requests.requestMatchers(blackListedEndpoint).denyAll());
    }
  }

  private void configureAllowedEndpoints(
      AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry requests) {
    openTmfSecurityProperties.getAllowedEndpoints().forEach(matcher ->
        requests.requestMatchers(matcher.getMethod(), matcher.getPath())
            .permitAll());
  }

  private void configureSecureEndpoints(
      AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry requests) {
    openTmfSecurityProperties.getSecureEndpoints().forEach(matcher ->
        requests.requestMatchers(matcher.getMethod(), matcher.getPath())
            .hasAnyAuthority(matcher.getRoles()));
  }

  /**
   * Besides the JWT wiring, applies the consumer-supplied handlers on the bearer-token path:
   * invalid / expired / malformed tokens (401) and insufficient-scope denials (403), which the
   * {@code BearerTokenAuthenticationFilter} handles before the {@code ExceptionTranslationFilter}
   * ever sees them.
   */
  private void configureResourceServer(
      OAuth2ResourceServerConfigurer<HttpSecurity> oauth2,
      AuthenticationEntryPoint entryPoint,
      AccessDeniedHandler accessDeniedHandler) {
    oauth2.jwt(jwtConfigurer -> {
      jwtConfigurer.decoder(jwtDecoder);
      jwtConfigurer.jwtAuthenticationConverter(jwtAuthenticationConverter());
    });
    if (entryPoint != null) {
      oauth2.authenticationEntryPoint(entryPoint);
    }
    if (accessDeniedHandler != null) {
      oauth2.accessDeniedHandler(accessDeniedHandler);
    }
  }

  private Converter<Jwt, AbstractAuthenticationToken> jwtAuthenticationConverter() {
    var grantedAuthoritiesConverter = new GrantedAuthoritiesConverter(
        authoritiesClaimName(openTmfSecurityProperties.getAuthoritiesClaim()));
    
    String primaryClaim = principalClaimName(openTmfSecurityProperties.getUserClaim());
    List<String> fallbackClaims = openTmfSecurityProperties.getFallbackUserClaims();
    
    // Always use ServletJwtPrincipalConverter which supports fallback to 'sub' claim
    return new ServletJwtPrincipalConverter(
        primaryClaim,
        fallbackClaims != null ? fallbackClaims : List.of(),
        grantedAuthoritiesConverter
    );
  }
}
