package org.opentmf.security.config.management;

import static org.opentmf.security.config.CommonConfig.authoritiesClaimName;
import static org.opentmf.security.config.CommonConfig.principalClaimName;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.opentmf.security.jwt.GrantedAuthoritiesConverter;
import org.opentmf.security.jwt.ServletJwtPrincipalConverter;
import org.opentmf.security.model.OpenTmfSecurityProperties;
import org.opentmf.security.model.OpenTmfSecurityProperties.Management;
import org.opentmf.security.model.OtherEndpoints;
import org.springframework.boot.actuate.autoconfigure.web.ManagementContextConfiguration;
import org.springframework.boot.actuate.autoconfigure.web.ManagementContextType;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.config.annotation.web.configurers.HttpBasicConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Registers a JWT-authenticated {@link SecurityFilterChain} into the management child
 * {@code ApplicationContext} when {@code management.server.port} differs from
 * {@code server.port}. Reuses the parent context's {@link JwtDecoder} so JWT decoding is
 * not duplicated.
 *
 * <p>{@link OpenTmfSecurityProperties} and {@link JwtDecoder} are resolved from the
 * parent (root) context via Spring's parent-first bean lookup. IntelliJ's Spring plugin
 * does not model that for {@link ManagementContextConfiguration} classes, so the
 * suppression below silences spurious "no bean found" inspection warnings on the
 * constructor parameters.
 *
 * @author Gokhan Demir
 */
@ManagementContextConfiguration(ManagementContextType.CHILD)
@Conditional(OnSeparateManagementPortCondition.class)
@ConditionalOnClass({SecurityFilterChain.class, HttpSecurity.class})
@ConditionalOnWebApplication(type = Type.SERVLET)
@EnableWebSecurity
@RequiredArgsConstructor
@SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection")
@Slf4j
public class ServletManagementSecurityAutoConfiguration {

  private final OpenTmfSecurityProperties properties;
  private final JwtDecoder jwtDecoder;

  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  SecurityFilterChain managementSecurityFilterChain(HttpSecurity http) {
    log.info("Registering JWT-authenticated SecurityFilterChain for the management port.");
    return http
        .securityMatcher("/**")
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
