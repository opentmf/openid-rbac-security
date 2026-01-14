package org.opentmf.security.service;

import java.net.URI;
import lombok.RequiredArgsConstructor;
import org.opentmf.security.model.Token;
import org.opentmf.security.model.TokenProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
@ConditionalOnWebApplication(type = Type.REACTIVE)
public class ReactiveTokenService implements TokenService {

  private static final WebClient webClient = WebClient.create();
  private final TokenProperties tokenProperties;

  @Override
  public Mono<String> getReactiveToken(URI uri, String user) {
    var userPass = tokenProperties.getUsers().get(user);
    var tokenRequestForm = BodyInserters
        .fromFormData("grant_type", "password")
        .with("username", userPass.getUsername())
        .with("password", userPass.getPassword())
        .with("scope", "openid");

    return postToken(uri, tokenRequestForm)
        .map(Token::getAccessToken);
  }

  @Override
  public String getToken(URI uri, String user) {
    return getReactiveToken(uri, user).block();
  }

  @Override
  public Mono<String> getReactiveToken(URI uri) {
    var tokenRequestForm = BodyInserters
        .fromFormData("grant_type", "client_credentials")
        .with("scope", "openid");

    return postToken(uri, tokenRequestForm)
        .map(Token::getAccessToken);
  }

  @Override
  public String getToken(URI uri) {
    return getReactiveToken(uri).block();
  }

  private Mono<Token> postToken(URI url,
      BodyInserters.FormInserter<String> tokenRequestForm) {
    var clientId = tokenProperties.getClientId();
    var clientSecret = tokenProperties.getClientSecret();

    return webClient
        .post()
        .uri(url)
        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        .accept(MediaType.APPLICATION_JSON)
        .body(tokenRequestForm)
        .headers(headers -> headers.setBasicAuth(clientId, clientSecret))
        .retrieve()
        .bodyToMono(Token.class);
  }
}
