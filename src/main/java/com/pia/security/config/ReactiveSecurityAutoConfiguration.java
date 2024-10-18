package com.pia.security.config;

import static com.pia.security.config.CommonConfig.authoritiesClaimName;
import static com.pia.security.config.CommonConfig.principalClaimName;
import static org.springframework.security.config.Customizer.withDefaults;

import com.pia.security.model.PiaSecurityProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity.AuthorizeExchangeSpec;
import org.springframework.security.config.web.server.ServerHttpSecurity.CorsSpec;
import org.springframework.security.config.web.server.ServerHttpSecurity.CsrfSpec;
import org.springframework.security.config.web.server.ServerHttpSecurity.FormLoginSpec;
import org.springframework.security.config.web.server.ServerHttpSecurity.HttpBasicSpec;
import org.springframework.security.config.web.server.ServerHttpSecurity.LogoutSpec;
import org.springframework.security.config.web.server.ServerHttpSecurity.OAuth2ResourceServerSpec;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtGrantedAuthoritiesConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.savedrequest.NoOpServerRequestCache;

/**
 * Pia Reactive Security configures according to the supplied PiaSecurityProperties.
 *
 * @author Gokhan Demir
 */
@AutoConfiguration(after = ReactiveJwtAutoConfiguration.class)
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
@EnableConfigurationProperties(PiaSecurityProperties.class)
@RequiredArgsConstructor
@ConditionalOnWebApplication(type = Type.REACTIVE)
public class ReactiveSecurityAutoConfiguration {

  private final PiaSecurityProperties piaSecurityProperties;
  private final ReactiveJwtDecoder reactiveJwtDecoder;

  @Bean
  public SecurityWebFilterChain reactiveSecurityFilterChain(ServerHttpSecurity http) {
    return http
        .requestCache(cache -> cache.requestCache(NoOpServerRequestCache.getInstance()))
        .csrf(CsrfSpec::disable)
        .formLogin(FormLoginSpec::disable)
        .httpBasic(HttpBasicSpec::disable)
        .logout(LogoutSpec::disable)
        .headers(withDefaults())
        .cors(CorsSpec::disable)
        .authorizeExchange(applyPiaSecurityDefinitions())
        .oauth2ResourceServer(configureResourceServer())
        .build();
  }

  private Customizer<OAuth2ResourceServerSpec> configureResourceServer() {
    return resourceServer ->
        resourceServer.jwt(jwt -> jwt
            .jwtDecoder(reactiveJwtDecoder)
            .jwtAuthenticationConverter(jwtAuthenticationConverter())
        );
  }

  private ReactiveJwtAuthenticationConverter jwtAuthenticationConverter() {
    var grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
    grantedAuthoritiesConverter.setAuthorityPrefix("");
    grantedAuthoritiesConverter.setAuthoritiesClaimName(
        authoritiesClaimName(piaSecurityProperties.getAuthoritiesClaim()));

    var grantedAuthoritiesConverterAdapter =
        new ReactiveJwtGrantedAuthoritiesConverterAdapter(grantedAuthoritiesConverter);

    var converter = new ReactiveJwtAuthenticationConverter();
    converter.setPrincipalClaimName(principalClaimName(piaSecurityProperties.getUserClaim()));
    converter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverterAdapter);

    return converter;
  }

  private Customizer<AuthorizeExchangeSpec> applyPiaSecurityDefinitions() {
    return exchanges -> {
      configureBlacklist(exchanges);
      configureWhiteList(exchanges);
      configureAllowedEndpoints(exchanges);
      configureSecureEndpoints(exchanges);
      exchanges.anyExchange().denyAll();
    };
  }

  private void configureAllowedEndpoints(AuthorizeExchangeSpec exchanges) {
    for (var allow : piaSecurityProperties.getAllowedEndpoints()) {
      exchanges.pathMatchers(allow.getMethod(), allow.getPath()).permitAll();
    }
  }

  private void configureWhiteList(AuthorizeExchangeSpec exchanges) {
    exchanges.pathMatchers(piaSecurityProperties.getWhitelist().toArray(String[]::new)).permitAll();
  }

  private void configureBlacklist(AuthorizeExchangeSpec exchanges) {
    exchanges.pathMatchers(piaSecurityProperties.getBlacklist().toArray(String[]::new)).denyAll();
  }

  private void configureSecureEndpoints(AuthorizeExchangeSpec exchanges) {
    for (var restricted : piaSecurityProperties.getSecureEndpoints()) {
      exchanges.pathMatchers(restricted.getMethod(), restricted.getPath())
          .hasAnyAuthority(restricted.getRoles());
    }
  }
}
