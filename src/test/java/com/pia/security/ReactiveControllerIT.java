package com.pia.security;

import static com.pia.security.util.TokenUtil.DIFFERENT_PROVIDER_TOKEN;
import static com.pia.security.util.TokenUtil.EXPIRED_READER_TOKEN;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.test.context.ActiveProfiles;

@ActiveProfiles("reactive")
class ReactiveControllerIT extends BaseReactiveIT{

  static {
    @SuppressWarnings("resource")
    KeycloakContainer keycloakContainer = new KeycloakContainer().withRealmImportFile(
        "realm/rehearsal-realm.json");
    keycloakContainer.setPortBindings(List.of("8191:8080"));
    keycloakContainer.start();
  }

  @Test
  void testJwtService_withValidToken_returnsValidResults() {
    var token = reactiveTokenService.getToken(getTokenUri(), "write");
    var jwt = jwtService.decodeJwt(token);
    assertNotNull(jwt.getClaim("groups"));
    assertFalse(jwtService.isExpiredToken(jwt));
    assertTrue(jwtService.isExpiredToken(EXPIRED_READER_TOKEN));
    assertThrows(InvalidBearerTokenException.class, () -> jwtService.isExpiredToken("bad token"));
    assertThrows(IllegalArgumentException.class, () -> jwtService.getJwtPrincipal(""));
    assertNotNull(jwtService.getJwtPrincipal(token));
    assertThrows(InvalidBearerTokenException.class, () -> jwtService.decodeJwt("bad token"));
    assertThrows(InvalidBearerTokenException.class, () -> jwtService.decodeJwt(DIFFERENT_PROVIDER_TOKEN));
    assertEquals(1, jwtService.getGrantedAuthorities(token, "sub").size());
    assertEquals(1, jwtService.getGrantedAuthorities(token, "groups").size());
    assertEquals(0, jwtService.getGrantedAuthorities(token, "resource_access.realm-management.bla").size());
    var realmAccessRoles = jwtService.getGrantedAuthorities(token, "realm_access.roles");
    assertEquals(3, realmAccessRoles.size());
    assertTrue(realmAccessRoles.contains(new SimpleGrantedAuthority("offline_access")));
    assertTrue(realmAccessRoles.contains(new SimpleGrantedAuthority("default-roles-rehearsal-realm")));
    assertTrue(realmAccessRoles.contains(new SimpleGrantedAuthority("uma_authorization")));
    var deepAuthorities = jwtService.getGrantedAuthorities(token, "resource_access.realm-management.roles");
    assertTrue(deepAuthorities.contains(new SimpleGrantedAuthority("view-users")));
    assertTrue(deepAuthorities.contains(new SimpleGrantedAuthority("query-groups")));
    assertTrue(deepAuthorities.contains(new SimpleGrantedAuthority("query-users")));
    assertEquals(3, deepAuthorities.size());
    Optional<Object> optionalClaim = jwtService.getJwtClaim(token, "given_name");
    assertTrue(optionalClaim.isPresent());
    assertEquals("Writer", optionalClaim.get());
    assertNotNull(jwtService.getJwtClaims(token, "roles"));
    assertNotNull(jwtService.getJwtClaims(token, "groups"));
    assertNotNull(jwtService.getJwtClaims(token, "sub"));
  }

  @Override
  String getToken(String scope) {
    return reactiveTokenService.getToken(getTokenUri(), scope);
  }

  private URI getTokenUri() {
    try {
      var jwkSetUri = piaSecurityProperties.getJwkSetUri().getURL().toString();
      return URI.create(jwkSetUri.substring(0, jwkSetUri.lastIndexOf('/') + 1) + "token");
    } catch (IOException e) {
      throw new IllegalArgumentException("jwk-set-uri is not a valid URL");
    }
  }
}
