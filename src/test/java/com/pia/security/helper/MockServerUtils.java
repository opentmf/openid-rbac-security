package com.pia.security.helper;

import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;
import static org.mockserver.model.MediaType.APPLICATION_JSON;

import org.mockserver.integration.ClientAndServer;
import org.mockserver.matchers.Times;
import org.mockserver.model.JsonBody;
import org.springframework.http.HttpStatus;

public class MockServerUtils {

  public static final ClientAndServer clientAndServer = new ClientAndServer();
  public static final String MOCKSERVER_URL = "http://localhost:" + clientAndServer.getLocalPort();

  public static void expectGet(String path, int count,
      HttpStatus responseStatus, String responseBody) {
    clientAndServer
        .when(
            request()
                .withMethod("GET")
                .withPath(path),
            Times.exactly(count))
        .respond(
            response()
                .withContentType(APPLICATION_JSON)
                .withBody(new JsonBody(responseBody))
                .withStatusCode(responseStatus.value()));
  }
}
