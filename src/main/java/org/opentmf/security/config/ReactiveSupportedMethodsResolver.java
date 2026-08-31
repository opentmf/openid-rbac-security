package org.opentmf.security.config;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Stream;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.reactive.result.method.RequestMappingInfo;
import org.springframework.web.reactive.result.method.RequestMappingInfoHandlerMapping;
import org.springframework.web.server.ServerWebExchange;

/**
 * Answers what HTTP methods the application actually serves on a given request path, by
 * consulting the same {@code RequestMappingInfo} objects Spring WebFlux dispatches with.
 *
 * <p>The reactive twin of {@link ServletSupportedMethodsResolver}; see that class for the
 * lazy-bean-lookup rationale, the live-read semantics and the coverage limits.
 *
 * @author Gokhan Demir
 */
@Slf4j
public class ReactiveSupportedMethodsResolver {

  private final HandlerMappingLookup<RequestMappingInfoHandlerMapping, RequestMappingInfo>
      mappings;

  /**
   * Creates a resolver over the given handler mappings.
   *
   * @param handlerMappings supplies the handler mappings of the context that actually dispatches
   *     the requests this resolver will be asked about, and only that context; called once on
   *     first use
   */
  public ReactiveSupportedMethodsResolver(
      Supplier<Stream<RequestMappingInfoHandlerMapping>> handlerMappings) {
    this.mappings =
        new HandlerMappingLookup<>(handlerMappings, mapping -> mapping.getHandlerMethods().keySet());
  }

  /** Primes the lazy handler-mapping lookup off the request path; failures retry on first use. */
  public void warmUp() {
    mappings.warmUp();
  }

  /**
   * Resolves the methods the application serves on the given exchange's path.
   *
   * @param exchange the exchange whose path to look up, never {@code null}
   * @return what the handler mappings declare, never {@code null}
   */
  public SupportedMethods resolve(ServerWebExchange exchange) {
    try {
      // The lazy lookup is inside the try on purpose: it can fail on a denial that arrives
      // during context shutdown, and SingletonSupplier does not cache a failure. LinkageError
      // is caught deliberately: on an application built without the matching web stack the
      // first touch of a handler-mapping type raises NoClassDefFoundError, which would
      // otherwise turn every denial into a 500.
      var entries = mappings.entries();
      if (entries.isEmpty()) {
        return SupportedMethods.notServed();
      }
      return match(entries, exchange);
    } catch (RuntimeException | LinkageError ex) {
      // A resolution failure must never turn a denial into a server error.
      log.debug("Could not resolve supported methods; leaving the denial as it is.", ex);
      return SupportedMethods.notServed();
    }
  }

  private static SupportedMethods match(
      List<HandlerMappingLookup.Entry<RequestMappingInfoHandlerMapping, RequestMappingInfo>>
          entries,
      ServerWebExchange exchange) {
    Set<HttpMethod> declared = new LinkedHashSet<>();
    boolean acceptsAnyMethod = false;
    for (var entry : entries) {
      for (RequestMappingInfo info : entry.infos()) {
        if (info.getPatternsCondition().getMatchingCondition(exchange) == null) {
          continue;
        }
        Set<RequestMethod> methods = info.getMethodsCondition().getMethods();
        if (methods.isEmpty()) {
          acceptsAnyMethod = true;
        }
        for (RequestMethod method : methods) {
          declared.add(method.asHttpMethod());
        }
      }
    }
    return new SupportedMethods(declared, acceptsAnyMethod);
  }
}
