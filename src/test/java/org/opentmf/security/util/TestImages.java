package org.opentmf.security.util;

import lombok.experimental.UtilityClass;

@UtilityClass
public class TestImages {

  /**
   * Pinned Keycloak image for the container-based ITs. Matches the default of
   * testcontainers-keycloak 4.2.1 — pinned explicitly because the no-arg
   * {@code KeycloakContainer()} constructor is deprecated and its default image will change in a
   * future version.
   */
  public static final String KEYCLOAK_IMAGE = "quay.io/keycloak/keycloak:26.6";
}
