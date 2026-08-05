package org.opentmf.security.config.management;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.opentmf.security.config.ReactiveJwtSupport;
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
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity.AuthorizeExchangeSpec;
import org.springframework.security.config.web.server.ServerHttpSecurity.CsrfSpec;
import org.springframework.security.config.web.server.ServerHttpSecurity.FormLoginSpec;
import org.springframework.security.config.web.server.ServerHttpSecurity.HttpBasicSpec;
import org.springframework.security.config.web.server.ServerHttpSecurity.LogoutSpec;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.savedrequest.NoOpServerRequestCache;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;

/**
 * Registers a JWT-authenticated {@link SecurityWebFilterChain} into the management child
 * {@code ApplicationContext} when {@code management.server.port} differs from
 * {@code server.port}. Reuses the parent context's {@link ReactiveJwtSupport} so decoders,
 * claim mapping and multi-issuer routing are identical to the main port and cannot drift.
 *
 * <p>{@link OpenTmfSecurityProperties} and {@link ReactiveJwtSupport} are resolved from
 * the parent (root) context via Spring's parent-first bean lookup. IntelliJ's Spring
 * plugin does not model that for {@link ManagementContextConfiguration} classes, so the
 * suppression below silences spurious "no bean found" inspection warnings on the
 * constructor parameters.
 *
 * @author Gokhan Demir
 */
@ManagementContextConfiguration(ManagementContextType.CHILD)
@Conditional(OnSeparateManagementPortCondition.class)
@ConditionalOnClass({SecurityWebFilterChain.class, ServerHttpSecurity.class})
@ConditionalOnWebApplication(type = Type.REACTIVE)
@EnableWebFluxSecurity
@RequiredArgsConstructor
@SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection")
@Slf4j
public class ReactiveManagementSecurityAutoConfiguration {

  private final OpenTmfSecurityProperties properties;
  private final ReactiveJwtSupport reactiveJwtSupport;

  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  SecurityWebFilterChain managementSecurityWebFilterChain(ServerHttpSecurity http) {
    log.info("Registering JWT-authenticated SecurityWebFilterChain for the management port.");
    return http
        .securityMatcher(ServerWebExchangeMatchers.pathMatchers("/**"))
        .requestCache(cache -> cache.requestCache(NoOpServerRequestCache.getInstance()))
        .csrf(CsrfSpec::disable)
        .formLogin(FormLoginSpec::disable)
        .httpBasic(HttpBasicSpec::disable)
        .logout(LogoutSpec::disable)
        .authorizeExchange(this::applyManagementAuthorization)
        .oauth2ResourceServer(reactiveJwtSupport::apply)
        .build();
  }

  private void applyManagementAuthorization(AuthorizeExchangeSpec exchanges) {
    Management management = properties.getManagement();
    management.getBlacklist().forEach(path -> exchanges.pathMatchers(path).denyAll());
    management.getWhitelist().forEach(path -> exchanges.pathMatchers(path).permitAll());
    management.getAllowedEndpoints().forEach(endpoint -> exchanges
        .pathMatchers(endpoint.getMethod(), endpoint.getPath())
        .permitAll());
    management.getSecureEndpoints().forEach(endpoint -> exchanges
        .pathMatchers(endpoint.getMethod(), endpoint.getPath())
        .hasAnyAuthority(endpoint.getRoles()));
    OtherEndpoints policy = management.getOtherEndpoints();
    switch (policy) {
      case ALLOW -> exchanges.anyExchange().permitAll();
      case DENY -> exchanges.anyExchange().denyAll();
      case AUTHENTICATED -> exchanges.anyExchange().authenticated();
    }
  }
}
