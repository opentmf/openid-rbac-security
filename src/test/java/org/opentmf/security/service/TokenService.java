package org.opentmf.security.service;

import java.net.URI;
import reactor.core.publisher.Mono;

/**
 * @author Gokhan Demir
 */
public interface TokenService {

  String getToken(URI uri, String user);

  Mono<String> getReactiveToken(URI uri, String token);
}
