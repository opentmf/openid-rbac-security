package org.opentmf.security.api.servlet;

import static org.springframework.web.servlet.function.RequestPredicates.GET;

import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication.Type;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.RouterFunctions;
import org.springframework.web.servlet.function.ServerResponse;

/**
 * A functional route beside the annotated controller, so the status matrix is proven against a
 * path that only {@code RouterFunctionMapping} knows about.
 *
 * @author Gokhan Demir
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication(type = Type.SERVLET)
public class ServletRoutes {

  @Bean
  RouterFunction<ServerResponse> functionalRoutes() {
    return RouterFunctions.route(GET("/fn"), request -> ServerResponse.ok().body("fn"));
  }
}
