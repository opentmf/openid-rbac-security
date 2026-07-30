package org.opentmf.security.config.management;

import static org.opentmf.security.config.CommonConfig.authoritiesClaimName;
import static org.opentmf.security.config.CommonConfig.principalClaimName;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.opentmf.security.config.ServletJwtAutoConfiguration;
import org.opentmf.security.jwt.GrantedAuthoritiesConverter;
import org.opentmf.security.jwt.ServletJwtPrincipalConverter;
import org.opentmf.security.model.OpenTmfSecurityProperties;
import org.opentmf.security.model.OpenTmfSecurityProperties.Management;
import org.opentmf.security.model.OtherEndpoints;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.boot.web.server.context.WebServerInitializedEvent;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.event.EventListener;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.HttpBasicConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

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
 * management server, so the matcher's initial {@code -1} sentinel never matches a real request.
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
  private final JwtDecoder jwtDecoder;
  private final AtomicInteger managementPort = new AtomicInteger(-1);

  @EventListener
  void captureManagementPort(WebServerInitializedEvent event) {
    if (MANAGEMENT_SERVER_NAMESPACE.equals(event.getApplicationContext().getServerNamespace())) {
      managementPort.set(event.getWebServer().getPort());
    }
  }

  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  SecurityFilterChain managementSecurityFilterChain(HttpSecurity http) {
    log.info("Registering JWT-authenticated SecurityFilterChain for the management port.");
    return http
        .securityMatcher(this::isManagementPortRequest)
        .sessionManagement(session -> session.sessionCreationPolicy(STATELESS))
        .csrf(CsrfConfigurer::disable)
        .formLogin(FormLoginConfigurer::disable)
        .httpBasic(HttpBasicConfigurer::disable)
        .logout(LogoutConfigurer::disable)
        .authorizeHttpRequests(this::applyManagementAuthorization)
        .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt
            .decoder(jwtDecoder)
            .jwtAuthenticationConverter(jwtAuthenticationConverter())))
        .build();
  }

  private boolean isManagementPortRequest(HttpServletRequest request) {
    return request.getLocalPort() == managementPort.get();
  }

  private void applyManagementAuthorization(
      AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry
          requests) {
    Management management = properties.getManagement();
    management.getBlacklist().forEach(path -> requests.requestMatchers(path).denyAll());
    management.getWhitelist().forEach(path -> requests.requestMatchers(path).permitAll());
    management.getAllowedEndpoints().forEach(endpoint -> requests
        .requestMatchers(endpoint.getMethod(), endpoint.getPath())
        .permitAll());
    management.getSecureEndpoints().forEach(endpoint -> requests
        .requestMatchers(endpoint.getMethod(), endpoint.getPath())
        .hasAnyAuthority(endpoint.getRoles()));
    OtherEndpoints policy = management.getOtherEndpoints();
    switch (policy) {
      case ALLOW -> requests.anyRequest().permitAll();
      case DENY -> requests.anyRequest().denyAll();
      case AUTHENTICATED -> requests.anyRequest().authenticated();
    }
  }

  private Converter<Jwt, AbstractAuthenticationToken> jwtAuthenticationConverter() {
    var grantedAuthoritiesConverter = new GrantedAuthoritiesConverter(
        authoritiesClaimName(properties.getAuthoritiesClaim()));
    String primaryClaim = principalClaimName(properties.getUserClaim());
    List<String> fallbackClaims = properties.getFallbackUserClaims();
    return new ServletJwtPrincipalConverter(
        primaryClaim,
        fallbackClaims != null ? fallbackClaims : List.of(),
        grantedAuthoritiesConverter);
  }
}
