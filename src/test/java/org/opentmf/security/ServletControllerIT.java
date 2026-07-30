package org.opentmf.security;

import static org.opentmf.security.util.TestImages.KEYCLOAK_IMAGE;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import java.util.List;
import org.springframework.test.context.ActiveProfiles;

@ActiveProfiles("servlet")
class ServletControllerIT extends BaseServletIT {

  static {
    @SuppressWarnings("resource")
    KeycloakContainer keycloakContainer = new KeycloakContainer(KEYCLOAK_IMAGE).withRealmImportFile(
            "realm/rehearsal.json");
    keycloakContainer.setPortBindings(List.of("8092:8080"));
    keycloakContainer.start();
  }

  @Override
  String getToken(String scope) {
    return servletTokenService.getToken(getTokenUri(), scope);
  }
}
