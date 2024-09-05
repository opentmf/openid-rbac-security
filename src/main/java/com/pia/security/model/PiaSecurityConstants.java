package com.pia.security.model;

import lombok.experimental.UtilityClass;

/**
 * @author Gokhan Demir
 */
@UtilityClass
public final class PiaSecurityConstants {

  public static final String[] SWAGGER = {"/v3/api-docs/**", "/webjars/**", "/swagger-ui/**",
      "/swagger-ui.html", "/configuration/ui", "/swagger-resources/**", "/configuration/security",
      "/swagger-ui.html", "/webjars/**"};
}
