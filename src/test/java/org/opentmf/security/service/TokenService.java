package org.opentmf.security.service;

import java.net.URI;
import reactor.core.publisher.Mono;

/**
 * @author Gokhan Demir
 */
public interface TokenService {

  String getToken(URI uri, String user);

  Mono<String> getReactiveToken(URI uri, String token);

  /**
   * Obtains an access token using client_credentials grant type.
   * This is useful for testing scenarios where user claims (like email) may not be present.
   *
   * @param uri the token endpoint URI
   * @return the access token
   */
  String getToken(URI uri);

  /**
   * Obtains an access token using client_credentials grant type (reactive).
   * This is useful for testing scenarios where user claims (like email) may not be present.
   *
   * @param uri the token endpoint URI
   * @return a Mono containing the access token
   */
  Mono<String> getReactiveToken(URI uri);
}
