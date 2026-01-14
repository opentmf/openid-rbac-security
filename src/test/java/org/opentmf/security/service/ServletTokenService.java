package org.opentmf.security.service;

import java.net.URI;
import lombok.RequiredArgsConstructor;
import org.opentmf.security.model.Token;
import org.opentmf.security.model.TokenProperties;
import org.opentmf.security.model.TokenProperties.UserPass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class ServletTokenService implements TokenService {

  private final TokenProperties tokenProperties;

  @Override
  public String getToken(URI uri, String user) {
    RestTemplate restTemplate = new RestTemplate();
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.MULTIPART_FORM_DATA);
    headers.setBasicAuth(tokenProperties.getClientId(), tokenProperties.getClientSecret());
    MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
    body.add("grant_type", "password");
    body.add("scope", "openid");
    UserPass userPass = tokenProperties.getUsers().get(user);
    body.add("username", userPass.getUsername());
    body.add("password", userPass.getPassword());
    HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);
    ResponseEntity<Token> response = restTemplate.postForEntity(uri, request, Token.class);
    Assert.notNull(response.getBody(), "Response body is null");
    return response.getBody().getAccessToken();
  }

  @Override
  public Mono<String> getReactiveToken(URI uri, String token) {
    throw new UnsupportedOperationException("I am not reactive.");
  }

  @Override
  public String getToken(URI uri) {
    RestTemplate restTemplate = new RestTemplate();
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
    headers.setBasicAuth(tokenProperties.getClientId(), tokenProperties.getClientSecret());
    MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
    body.add("grant_type", "client_credentials");
    body.add("scope", "openid");
    HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);
    ResponseEntity<Token> response = restTemplate.postForEntity(uri, request, Token.class);
    Assert.notNull(response.getBody(), "Response body is null");
    return response.getBody().getAccessToken();
  }

  @Override
  public Mono<String> getReactiveToken(URI uri) {
    throw new UnsupportedOperationException("I am not reactive.");
  }
}
