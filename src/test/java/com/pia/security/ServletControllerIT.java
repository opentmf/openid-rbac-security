package com.pia.security;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import java.io.IOException;
import java.net.URI;
import java.util.List;
import org.springframework.test.context.ActiveProfiles;

@ActiveProfiles("servlet")
class ServletControllerIT extends BaseServletIT {

  static {
    @SuppressWarnings("resource")
    KeycloakContainer keycloakContainer = new KeycloakContainer().withRealmImportFile(
        "realm/rehearsal-realm.json");
    keycloakContainer.setPortBindings(List.of("8092:8080"));
    keycloakContainer.start();
  }

  @Override
  String getToken(String scope) {
    return servletTokenService.getToken(getTokenUri(), scope);
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
