package org.opentmf.security.config;

import static org.opentmf.security.config.CommonConfig.resolveIssuers;

import jakarta.servlet.http.HttpServletRequest;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.opentmf.security.jwt.CompositeJwtDecoder;
import org.opentmf.security.jwt.GrantedAuthoritiesConverter;
import org.opentmf.security.jwt.ServletJwtPrincipalConverter;
import org.opentmf.security.model.OpenTmfSecurityProperties;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;

/**
 * Everything the servlet filter chains need to validate tokens, in one place so the main-port
 * and management-port chains cannot drift apart.
 *
 * <p>Single-issuer mode (no {@code opentmf.security.issuers}) wires one decoder and one
 * converter exactly as every release before 2.3.0 did. Multi-issuer mode instead wires an
 * {@link AuthenticationManagerResolver} that selects the decoder AND the claim mapping by the
 * token's {@code iss}; a token whose issuer is unknown or absent is rejected with
 * {@code 401 invalid_token} rather than falling back to another issuer.
 *
 * <p>The two are mutually exclusive by Spring Security's own rule: configuring an
 * authentication-manager resolver forbids also configuring {@code jwt()} on the same
 * resource-server configurer, which is why {@link #apply(OAuth2ResourceServerConfigurer)}
 * owns the branch instead of each chain repeating it.
 *
 * @author Gokhan Demir
 */
@Slf4j
public class ServletJwtSupport {

  private final AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver;
  private final Converter<Jwt, AbstractAuthenticationToken> authenticationConverter;

  /**
   * The decoder bean exposed to {@code JwtService} and to consumers injecting
   * {@link JwtDecoder}. In multi-issuer mode this routes by {@code iss} so those callers work
   * across every configured issuer.
   */
  @Getter
  private final JwtDecoder decoder;

  public ServletJwtSupport(OpenTmfSecurityProperties properties) {
    List<ResolvedIssuer> issuers = resolveIssuers(properties);
    if (issuers.size() == 1 && !issuers.get(0).pinsIssuer()) {
      ResolvedIssuer single = issuers.get(0);
      this.decoder = JwtDecoderFactory.servletDecoder(single);
      this.authenticationConverter = converterFor(single);
      this.authenticationManagerResolver = null;
      return;
    }
    Map<String, JwtDecoder> decoders = new LinkedHashMap<>();
    Map<String, AuthenticationManager> managers = new LinkedHashMap<>();
    for (ResolvedIssuer issuer : issuers) {
      JwtDecoder issuerDecoder = JwtDecoderFactory.servletDecoder(issuer);
      decoders.put(issuer.issuer(), issuerDecoder);
      managers.put(issuer.issuer(), authenticationManager(issuer, issuerDecoder));
      log.info("Trusting JWT issuer '{}' ({}), roles from claim '{}', principal from claim '{}',"
              + " audience validation {}.",
          issuer.name(), issuer.issuer(), issuer.authoritiesClaim(), issuer.userClaim(),
          issuer.audiences().isEmpty() ? "disabled" : "restricted to " + issuer.audiences());
    }
    this.decoder = new CompositeJwtDecoder(decoders);
    this.authenticationConverter = null;
    this.authenticationManagerResolver =
        new JwtIssuerAuthenticationManagerResolver(managers::get);
  }

  /**
   * Applies token validation to a resource-server configurer — the single place that decides
   * between the single-issuer and multi-issuer wiring.
   */
  public void apply(OAuth2ResourceServerConfigurer<HttpSecurity> oauth2) {
    if (authenticationManagerResolver != null) {
      oauth2.authenticationManagerResolver(authenticationManagerResolver);
    } else {
      oauth2.jwt(jwt -> jwt.decoder(decoder).jwtAuthenticationConverter(authenticationConverter));
    }
  }

  private static AuthenticationManager authenticationManager(ResolvedIssuer issuer,
      JwtDecoder issuerDecoder) {
    JwtAuthenticationProvider provider = new JwtAuthenticationProvider(issuerDecoder);
    provider.setJwtAuthenticationConverter(converterFor(issuer));
    return new ProviderManager(provider);
  }

  private static Converter<Jwt, AbstractAuthenticationToken> converterFor(ResolvedIssuer issuer) {
    return new ServletJwtPrincipalConverter(
        issuer.userClaim(),
        issuer.fallbackUserClaims(),
        new GrantedAuthoritiesConverter(issuer.authoritiesClaim()));
  }
}
