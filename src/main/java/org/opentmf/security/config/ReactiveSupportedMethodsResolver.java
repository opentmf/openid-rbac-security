package org.opentmf.security.config;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.util.function.SingletonSupplier;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.reactive.result.method.RequestMappingInfo;
import org.springframework.web.reactive.result.method.RequestMappingInfoHandlerMapping;
import org.springframework.web.server.ServerWebExchange;

/**
 * Answers what HTTP methods the application actually serves on a given request path, by
 * consulting the same {@code RequestMappingInfo} objects Spring WebFlux dispatches with.
 *
 * <p>The reactive twin of {@link ServletSupportedMethodsResolver}; see that class for the
 * lazy-snapshot rationale and the coverage limits.
 *
 * @author Gokhan Demir
 */
@Slf4j
public class ReactiveSupportedMethodsResolver {

  private final Supplier<Set<RequestMappingInfo>> mappings;

  /**
   * Creates a resolver over the given handler mappings.
   *
   * @param handlerMappings supplies the handler mappings of the context that actually dispatches
   *     the requests this resolver will be asked about, called once on first use
   */
  public ReactiveSupportedMethodsResolver(
      Supplier<Stream<RequestMappingInfoHandlerMapping>> handlerMappings) {
    this.mappings = SingletonSupplier.of(() -> snapshot(handlerMappings));
  }

  private static Set<RequestMappingInfo> snapshot(
      Supplier<Stream<RequestMappingInfoHandlerMapping>> handlerMappings) {
    Set<RequestMappingInfo> infos = handlerMappings.get()
        .flatMap(mapping -> mapping.getHandlerMethods().keySet().stream())
        .collect(Collectors.toUnmodifiableSet());
    log.debug("Captured {} request mappings for HTTP method resolution.", infos.size());
    return infos;
  }

  /**
   * Resolves the methods the application serves on the given exchange's path.
   *
   * @param exchange the exchange whose path to look up, never {@code null}
   * @return what the handler mappings declare, never {@code null}
   */
  public SupportedMethods resolve(ServerWebExchange exchange) {
    Set<RequestMappingInfo> infos = mappings.get();
    if (infos.isEmpty()) {
      return SupportedMethods.notServed();
    }
    try {
      return match(infos, exchange);
    } catch (RuntimeException ex) {
      // A resolution failure must never turn a denial into a server error.
      log.debug("Could not resolve supported methods; leaving the denial as it is.", ex);
      return SupportedMethods.notServed();
    }
  }

  private static SupportedMethods match(
      Set<RequestMappingInfo> infos, ServerWebExchange exchange) {
    Set<HttpMethod> declared = new LinkedHashSet<>();
    boolean pathServed = false;
    boolean acceptsAnyMethod = false;
    for (RequestMappingInfo info : infos) {
      if (info.getPatternsCondition().getMatchingCondition(exchange) == null) {
        continue;
      }
      pathServed = true;
      Set<RequestMethod> methods = info.getMethodsCondition().getMethods();
      if (methods.isEmpty()) {
        acceptsAnyMethod = true;
      }
      for (RequestMethod method : methods) {
        declared.add(HttpMethod.valueOf(method.name()));
      }
    }
    return pathServed
        ? new SupportedMethods(declared, true, acceptsAnyMethod)
        : SupportedMethods.notServed();
  }
}
