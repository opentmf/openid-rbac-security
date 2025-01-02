package com.pia.security.util;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.SignedJWT;
import java.io.FileInputStream;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.Resource;
import org.springframework.util.ResourceUtils;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@RequiredArgsConstructor
public class ReactiveResourceRetriever extends BaseResourceRetriever {

  private final Resource jwkSetUri;

  public Flux<JWK> getKeys(SignedJWT signedJWT) {
    try {
      var url = jwkSetUri.getURL();
      String content = contents(new FileInputStream(ResourceUtils.getFile(url)));

      return Mono.just(content).flatMapMany(jwkSetJson -> {
        try {
          JWKSet jwkSet = JWKSet.parse(jwkSetJson);
          return Flux.fromIterable(jwkSet.getKeys());
        } catch (Exception e) {
          return Flux.error(new IllegalStateException("Failed to parse JWK Set", e));
        }
      });
    } catch (IOException e) {
      throw new IllegalArgumentException("Exception during JWK Set retrieval", e);
    }
  }
}
