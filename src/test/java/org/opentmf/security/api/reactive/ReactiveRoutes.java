package org.opentmf.security.api.reactive;

import static org.springframework.web.reactive.function.server.RequestPredicates.GET;

import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerResponse;

/**
 * The reactive twin of {@code ServletRoutes}: a path only {@code RouterFunctionMapping} knows.
 *
 * @author Gokhan Demir
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication(type = Type.REACTIVE)
public class ReactiveRoutes {

  @Bean
  RouterFunction<ServerResponse> functionalRoutes() {
    return RouterFunctions.route(GET("/fn"), request -> ServerResponse.ok().bodyValue("fn"));
  }
}
