package org.opentmf.security.config;

import static org.opentmf.security.config.CommonConfig.resolveIssuers;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.opentmf.security.jwt.CompositeReactiveJwtDecoder;
import org.opentmf.security.jwt.GrantedAuthoritiesConverter;
import org.opentmf.security.jwt.ReactiveJwtPrincipalConverter;
import org.opentmf.security.model.OpenTmfSecurityProperties;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.config.web.server.ServerHttpSecurity.OAuth2ResourceServerSpec;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerReactiveAuthenticationManagerResolver;
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Reactive twin of {@link ServletJwtSupport}: same single-issuer / multi-issuer branch, same
 * per-issuer claim mapping, expressed with the reactive types.
 *
 * @author Gokhan Demir
 */
@Slf4j
public class ReactiveJwtSupport {

  private final ReactiveAuthenticationManagerResolver<ServerWebExchange>
      authenticationManagerResolver;
  private final Converter<Jwt, Mono<? extends AbstractAuthenticationToken>> authenticationConverter;

  /**
   * The decoder bean exposed to consumers injecting {@link ReactiveJwtDecoder}. In
   * multi-issuer mode this routes by {@code iss}.
   */
  @Getter
  private final ReactiveJwtDecoder decoder;

  public ReactiveJwtSupport(OpenTmfSecurityProperties properties) {
    List<ResolvedIssuer> issuers = resolveIssuers(properties);
    if (issuers.size() == 1 && !issuers.get(0).pinsIssuer()) {
      ResolvedIssuer single = issuers.get(0);
      this.decoder = JwtDecoderFactory.reactiveDecoder(single);
      this.authenticationConverter = converterFor(single);
      this.authenticationManagerResolver = null;
      return;
    }
    Map<String, ReactiveJwtDecoder> decoders = new LinkedHashMap<>();
    Map<String, ReactiveAuthenticationManager> managers = new LinkedHashMap<>();
    for (ResolvedIssuer issuer : issuers) {
      ReactiveJwtDecoder issuerDecoder = JwtDecoderFactory.reactiveDecoder(issuer);
      decoders.put(issuer.issuer(), issuerDecoder);
      managers.put(issuer.issuer(), authenticationManager(issuer, issuerDecoder));
      log.info("Trusting JWT issuer '{}' ({}), roles from claim '{}', principal from claim '{}',"
              + " audience validation {}.",
          issuer.name(), issuer.issuer(), issuer.authoritiesClaim(), issuer.userClaim(),
          issuer.audiences().isEmpty() ? "disabled" : "restricted to " + issuer.audiences());
    }
    this.decoder = new CompositeReactiveJwtDecoder(decoders);
    this.authenticationConverter = null;
    this.authenticationManagerResolver = new JwtIssuerReactiveAuthenticationManagerResolver(
        issuer -> Mono.justOrEmpty(managers.get(issuer)));
  }

  /**
   * Applies token validation to a reactive resource-server spec — the single place that
   * decides between the single-issuer and multi-issuer wiring.
   */
  public void apply(OAuth2ResourceServerSpec oauth2) {
    if (authenticationManagerResolver != null) {
      oauth2.authenticationManagerResolver(authenticationManagerResolver);
    } else {
      oauth2.jwt(jwt -> jwt.jwtDecoder(decoder)
          .jwtAuthenticationConverter(authenticationConverter));
    }
  }

  private static ReactiveAuthenticationManager authenticationManager(ResolvedIssuer issuer,
      ReactiveJwtDecoder issuerDecoder) {
    JwtReactiveAuthenticationManager manager = new JwtReactiveAuthenticationManager(issuerDecoder);
    manager.setJwtAuthenticationConverter(converterFor(issuer));
    return manager;
  }

  private static Converter<Jwt, Mono<? extends AbstractAuthenticationToken>> converterFor(
      ResolvedIssuer issuer) {
    return new ReactiveJwtPrincipalConverter(
        issuer.userClaim(),
        issuer.fallbackUserClaims(),
        new GrantedAuthoritiesConverter(issuer.authoritiesClaim()));
  }
}
