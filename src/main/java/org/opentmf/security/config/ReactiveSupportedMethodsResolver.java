package org.opentmf.security.config;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;
import java.util.stream.Stream;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.PathContainer;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.reactive.HandlerMapping;
import org.springframework.web.reactive.resource.ResourceHandlerUtils;
import org.springframework.web.reactive.resource.ResourceResolver;
import org.springframework.web.reactive.resource.ResourceResolverChain;
import org.springframework.web.reactive.resource.ResourceWebHandler;
import org.springframework.web.reactive.result.method.RequestMappingInfo;
import org.springframework.web.reactive.result.method.RequestMappingInfoHandlerMapping;
import org.springframework.web.server.MethodNotAllowedException;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.ServerWebExchangeDecorator;
import org.springframework.web.util.pattern.PathPattern;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Answers whether the application serves an exchange's path at all, and with which HTTP
 * methods, by consulting the same {@code HandlerMapping}s the {@code DispatcherHandler}
 * dispatches with, in the same order, stopping at the first that claims the path.
 *
 * <p>The reactive twin of {@link ServletSupportedMethodsResolver}; see that class for the
 * design: annotation mappings read through their infos, every other mapping asked for a handler
 * the way the dispatcher asks it, a static-resource handler claiming the path only when the
 * resource resolves, and a probe exchange whose attributes are its own.
 *
 * @author Gokhan Demir
 */
@Slf4j
public class ReactiveSupportedMethodsResolver {

  /** A handler whose methods are not knowable from outside: the request goes on to it. */
  private static final SupportedMethods ANY_METHOD = new SupportedMethods(Set.of(), true);

  /** What {@code ResourceWebHandler} supports; it keeps the set to itself. */
  private static final SupportedMethods RESOURCE_METHODS =
      new SupportedMethods(Set.of(HttpMethod.GET, HttpMethod.HEAD), false);

  private final HandlerMappingLookup<HandlerMapping, RequestMappingInfo> mappings;

  /**
   * Creates a resolver over the given handler mappings.
   *
   * @param handlerMappings supplies the handler mappings of the context that actually dispatches
   *     the exchanges this resolver will be asked about, and only that context; called once on
   *     first use
   */
  public ReactiveSupportedMethodsResolver(Supplier<Stream<HandlerMapping>> handlerMappings) {
    this.mappings =
        new HandlerMappingLookup<>(handlerMappings, ReactiveSupportedMethodsResolver::infosOf);
  }

  private static Collection<RequestMappingInfo> infosOf(HandlerMapping mapping) {
    return mapping instanceof RequestMappingInfoHandlerMapping annotated
        ? annotated.getHandlerMethods().keySet()
        : List.of();
  }

  /** Primes the lazy handler-mapping lookup off the request path; failures retry on first use. */
  public void warmUp() {
    mappings.warmUp();
  }

  /**
   * Resolves what the application serves on the given exchange's path.
   *
   * @param exchange the exchange whose path to look up, never {@code null}
   * @return what the handler mappings say — the path is served with these methods, or by no
   *     handler at all — or empty when they could not be consulted, in which case the exchange
   *     must be left to the access rules rather than answered from a guess. Never an empty
   *     {@code Mono}
   */
  public Mono<Optional<SupportedMethods>> resolve(ServerWebExchange exchange) {
    return Mono.defer(() -> {
      // The lazy lookup is inside the deferral on purpose: it can fail on an exchange that
      // arrives during context shutdown, and SingletonSupplier does not cache a failure. A
      // LinkageError from an application built without the matching web stack travels the
      // same error path, so it can never turn every exchange into a 500.
      var entries = mappings.entries();
      var probe = new ProbeExchange(exchange);
      return Flux.fromIterable(entries)
          .concatMap(entry -> claim(entry, probe))
          .next()
          .defaultIfEmpty(SupportedMethods.notServed())
          .map(Optional::of);
    }).onErrorResume(ex -> {
      // A resolution failure must never turn a request into a server error, nor into a 404 the
      // mappings never said: the access rules answer, as they did before the matrix existed.
      log.debug("Could not resolve the handler mappings; leaving the request to the access rules.",
          ex);
      return Mono.just(Optional.empty());
    });
  }

  /**
   * What one mapping claims for the path: empty when it does not claim it, and the dispatcher
   * would move on to the next; {@link SupportedMethods#notServed()} when it claims the path
   * only to answer {@code 404} itself, which ends the lookup as it would end the dispatch.
   */
  private static Mono<SupportedMethods> claim(
      HandlerMappingLookup.Entry<HandlerMapping, RequestMappingInfo> entry, ProbeExchange probe) {
    HandlerMapping mapping = entry.mapping();
    if (mapping instanceof RequestMappingInfoHandlerMapping) {
      SupportedMethods matched = matchInfos(entry.infos(), probe);
      return matched.pathServed() ? Mono.just(matched) : Mono.empty();
    }
    return mapping.getHandler(probe)
        .flatMap(handler -> handler instanceof ResourceWebHandler resources
            ? resourceClaim(resources, probe)
            : Mono.just(ANY_METHOD))
        // A mapping that answers "path yes, method no" the way the dispatcher would see it.
        .onErrorResume(MethodNotAllowedException.class,
            ex -> Mono.just(declaring(ex.getSupportedMethods())));
  }

  private static SupportedMethods declaring(Collection<HttpMethod> methods) {
    return methods.isEmpty()
        ? ANY_METHOD
        : new SupportedMethods(new LinkedHashSet<>(methods), false);
  }

  /**
   * A resource handler serves the path only when the resource exists — resolved the way the
   * handler itself resolves it, from the attributes its mapping just set on the probe, through
   * its own resolvers and locations. Boot's default handler on {@code /**} would otherwise claim
   * every path there is. A miss ends the lookup with "not served": the dispatcher would dispatch
   * to this handler and get its {@code 404}.
   */
  private static Mono<SupportedMethods> resourceClaim(
      ResourceWebHandler handler, ProbeExchange probe) {
    PathPattern pattern = probe.getAttribute(HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE);
    PathContainer pathWithinMapping =
        probe.getAttribute(HandlerMapping.PATH_WITHIN_HANDLER_MAPPING_ATTRIBUTE);
    if (pattern == null || pathWithinMapping == null) {
      // Matched some way this resolver cannot retrace: let the handler answer for itself.
      return Mono.just(RESOURCE_METHODS);
    }
    String raw =
        pattern.hasPatternSyntax() ? pathWithinMapping.value() : pattern.getPatternString();
    String path = ResourceHandlerUtils.normalizeInputPath(raw);
    if (ResourceHandlerUtils.shouldIgnoreInputPath(path)) {
      return Mono.just(SupportedMethods.notServed());
    }
    return ResolverChain.of(handler.getResourceResolvers())
        .resolveResource(probe, path, handler.getLocations())
        .map(resource -> RESOURCE_METHODS)
        .defaultIfEmpty(SupportedMethods.notServed());
  }

  /** What the annotation mappings declare for the exchange's path. */
  private static SupportedMethods matchInfos(
      Collection<RequestMappingInfo> infos, ServerWebExchange probe) {
    Set<HttpMethod> declared = new LinkedHashSet<>();
    boolean acceptsAnyMethod = false;
    for (RequestMappingInfo info : infos) {
      if (info.getPatternsCondition().getMatchingCondition(probe) == null) {
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
    return new SupportedMethods(declared, acceptsAnyMethod);
  }

  /**
   * The handler's resolvers chained the way the handler itself chains them. Spring's own
   * {@code DefaultResourceResolverChain} is not public, so this is that class, line for line.
   */
  private record ResolverChain(ResourceResolver resolver, ResourceResolverChain next)
      implements ResourceResolverChain {

    private static final ResolverChain END = new ResolverChain(null, null);

    private static ResourceResolverChain of(List<ResourceResolver> resolvers) {
      ResolverChain chain = END;
      ListIterator<ResourceResolver> it = resolvers.listIterator(resolvers.size());
      while (it.hasPrevious()) {
        chain = new ResolverChain(it.previous(), chain);
      }
      return chain;
    }

    @Override
    public Mono<Resource> resolveResource(
        ServerWebExchange exchange, String requestPath, List<? extends Resource> locations) {
      return resolver != null
          ? resolver.resolveResource(exchange, requestPath, locations, next)
          : Mono.empty();
    }

    @Override
    public Mono<String> resolveUrlPath(String resourcePath, List<? extends Resource> locations) {
      return resolver != null
          ? resolver.resolveUrlPath(resourcePath, locations, next)
          : Mono.empty();
    }
  }

  /**
   * The exchange as the mappings see it: same request and response, but attributes of its own,
   * so whatever a mapping records while answering — best-match attributes, a router function's
   * request — stays here and the real exchange reaches the dispatcher untouched.
   */
  private static final class ProbeExchange extends ServerWebExchangeDecorator {

    private final Map<String, Object> attributes;

    private ProbeExchange(ServerWebExchange delegate) {
      super(delegate);
      this.attributes = new ConcurrentHashMap<>(delegate.getAttributes());
    }

    @Override
    public Map<String, Object> getAttributes() {
      return attributes;
    }
  }
}
