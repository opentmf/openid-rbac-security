package org.opentmf.security.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.opentmf.security.config.CommonConfig.resolveIssuers;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.opentmf.security.model.IssuerProperties;
import org.opentmf.security.model.OpenTmfSecurityProperties;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

/**
 * Pins how the two configuration styles flatten into issuers, in particular that per-issuer
 * settings inherit the top-level ones — the property that lets a consumer state the common role
 * vocabulary once and override it only for the provider that deviates.
 *
 * @author Gokhan Demir
 */
class CommonConfigResolveIssuersTest {

  private static final Resource JWK_SET = new ClassPathResource("jwk-set.json");

  @Test
  void noIssuers_yieldsOneEntryThatDoesNotPinAnIssuer() {
    OpenTmfSecurityProperties properties = new OpenTmfSecurityProperties();
    properties.setJwkSetUri(JWK_SET);
    properties.setUserClaim("email");
    properties.setAuthoritiesClaim("groups");
    properties.setFallbackUserClaims(List.of("azp"));

    List<ResolvedIssuer> resolved = resolveIssuers(properties);

    assertThat(resolved).hasSize(1);
    ResolvedIssuer single = resolved.get(0);
    assertThat(single.pinsIssuer()).isFalse();
    assertThat(single.issuer()).isNull();
    assertThat(single.userClaim()).isEqualTo("email");
    assertThat(single.authoritiesClaim()).isEqualTo("groups");
    assertThat(single.fallbackUserClaims()).containsExactly("azp");
    assertThat(single.audiences()).isEmpty();
  }

  @Test
  void noIssuersAndNoClaimSettings_fallsBackToTheLibraryDefaults() {
    OpenTmfSecurityProperties properties = new OpenTmfSecurityProperties();
    properties.setJwkSetUri(JWK_SET);

    ResolvedIssuer single = resolveIssuers(properties).get(0);

    assertThat(single.userClaim()).isEqualTo("sub");
    assertThat(single.authoritiesClaim()).isEqualTo("roles");
    assertThat(single.fallbackUserClaims()).isEmpty();
  }

  @Test
  void entriesInheritTheTopLevelClaimSettingsTheyDoNotDeclare() {
    OpenTmfSecurityProperties properties = new OpenTmfSecurityProperties();
    properties.setUserClaim("sub");
    properties.setAuthoritiesClaim("groups");
    properties.setFallbackUserClaims(List.of("client_id", "azp"));
    properties.setIssuers(List.of(
        entry("keycloak", "https://keycloak.test/realms/dnms", null, null),
        entry("entra", "https://login.microsoftonline.com/tenant/v2.0", "oid", "roles")));

    List<ResolvedIssuer> resolved = resolveIssuers(properties);

    ResolvedIssuer keycloak = resolved.get(0);
    assertThat(keycloak.pinsIssuer()).isTrue();
    assertThat(keycloak.userClaim()).isEqualTo("sub");
    assertThat(keycloak.authoritiesClaim()).isEqualTo("groups");
    assertThat(keycloak.fallbackUserClaims()).containsExactly("client_id", "azp");

    ResolvedIssuer entra = resolved.get(1);
    assertThat(entra.userClaim()).isEqualTo("oid");
    assertThat(entra.authoritiesClaim()).isEqualTo("roles");
    assertThat(entra.fallbackUserClaims()).containsExactly("client_id", "azp");
  }

  @Test
  void anEntryWithoutANameIsLabelledByItsIssuer() {
    OpenTmfSecurityProperties properties = new OpenTmfSecurityProperties();
    properties.setIssuers(List.of(entry(null, "https://keycloak.test/realms/dnms", null, null)));

    assertThat(resolveIssuers(properties).get(0).name())
        .isEqualTo("https://keycloak.test/realms/dnms");
  }

  @Test
  void anEmptyFallbackListOnAnEntryOptsOutOfTheInheritedOne() {
    OpenTmfSecurityProperties properties = new OpenTmfSecurityProperties();
    properties.setFallbackUserClaims(List.of("client_id"));
    IssuerProperties entry = entry("entra", "https://entra.test/v2.0", null, null);
    entry.setFallbackUserClaims(List.of());
    properties.setIssuers(List.of(entry));

    assertThat(resolveIssuers(properties).get(0).fallbackUserClaims()).isEmpty();
  }

  private static IssuerProperties entry(String name, String issuer, String userClaim,
      String authoritiesClaim) {
    IssuerProperties properties = new IssuerProperties();
    properties.setName(name);
    properties.setIssuer(issuer);
    properties.setJwkSetUri(JWK_SET);
    properties.setUserClaim(userClaim);
    properties.setAuthoritiesClaim(authoritiesClaim);
    return properties;
  }
}
