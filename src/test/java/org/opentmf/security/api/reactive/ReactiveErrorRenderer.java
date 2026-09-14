package org.opentmf.security.api.reactive;

import java.nio.charset.StandardCharsets;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebExceptionHandler;
import reactor.core.publisher.Mono;

/**
 * The reactive application's own rendering of a {@code ResponseStatusException} — what a
 * consumer's {@code ErrorWebExceptionHandler} does. Marks its output so a test can tell the
 * application's body from Boot's default one; every other exception is left to Boot.
 *
 * @author Gokhan Demir
 */
@Component
@Order(-3)
@ConditionalOnWebApplication(type = Type.REACTIVE)
public class ReactiveErrorRenderer implements WebExceptionHandler {

  public static final String RENDERER_HEADER = "X-Error-Renderer";
  public static final String RENDERER = "application";

  @Override
  public Mono<Void> handle(ServerWebExchange exchange, Throwable ex) {
    if (!(ex instanceof ResponseStatusException statusException)) {
      return Mono.error(ex);
    }
    var response = exchange.getResponse();
    response.setStatusCode(statusException.getStatusCode());
    response.getHeaders().setContentType(MediaType.APPLICATION_PROBLEM_JSON);
    response.getHeaders().set(RENDERER_HEADER, RENDERER);
    byte[] body = ("{\"status\":" + statusException.getStatusCode().value() + "}")
        .getBytes(StandardCharsets.UTF_8);
    return response.writeWith(Mono.just(response.bufferFactory().wrap(body)));
  }
}
