package org.opentmf.security.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.ListIterator;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Stream;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.PathContainer;
import org.springframework.util.PathMatcher;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.HandlerExecutionChain;
import org.springframework.web.servlet.HandlerMapping;
import org.springframework.web.servlet.handler.AbstractHandlerMapping;
import org.springframework.web.servlet.handler.AbstractUrlHandlerMapping;
import org.springframework.web.servlet.mvc.condition.RequestCondition;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.RequestMappingInfoHandlerMapping;
import org.springframework.web.servlet.resource.ResourceHandlerUtils;
import org.springframework.web.servlet.resource.ResourceHttpRequestHandler;
import org.springframework.web.servlet.resource.ResourceResolver;
import org.springframework.web.servlet.resource.ResourceResolverChain;
import org.springframework.web.util.ServletRequestPathUtils;
import org.springframework.web.util.UrlPathHelper;
import org.springframework.web.util.pattern.PathPattern;

/**
 * Answers whether the application serves a request's path at all, and with which HTTP methods,
 * by consulting the same {@code HandlerMapping}s the {@code DispatcherServlet} dispatches with,
 * in the same order, stopping at the first that claims the path — as the dispatcher would.
 *
 * <p>Annotation-based mappings are read through their {@code RequestMappingInfo}s, matched on
 * the path alone (Spring's own patterns condition, so no pattern semantics are re-implemented)
 * so that the declared methods are known without a method-mismatch exception. Every other
 * mapping — functional routes, resource handlers, whatever a consumer registers — is asked for
 * a handler the way the dispatcher asks it. A static-resource handler claims the path only when
 * the resource actually resolves: Boot maps one to {@code /**} by default, and without that
 * check no path would ever be unknown. The methods of a handler that is not annotation-based
 * are its own business, so the request is left to proceed to it; a resource handler is the one
 * exception, since it publishes the methods it supports.
 *
 * <p>Every mapping is asked through a probe request whose attributes are its own, so nothing a
 * mapping caches while answering — the parsed path, best-match attributes, CORS results — leaks
 * into the request that the dispatcher will parse again for itself.
 *
 * <p>The handler-mapping <em>beans</em> are looked up once, lazily, on first use — never while
 * the security filter chain is being built, which would force Spring MVC's infrastructure to
 * initialize too early. Their mappings are read through a briefly cached view (at most one
 * second stale — see {@link HandlerMappingLookup}), so a consumer that registers or removes
 * mappings at runtime is answered from what the application serves now.
 *
 * @author Gokhan Demir
 */
@Slf4j
public class ServletSupportedMethodsResolver {

  /** A handler whose methods are not knowable from outside: the request goes on to it. */
  private static final SupportedMethods ANY_METHOD = new SupportedMethods(Set.of(), true);

  private final HandlerMappingLookup<HandlerMapping, RequestMappingInfo> mappings;

  /**
   * Creates a resolver over the given handler mappings.
   *
   * @param handlerMappings supplies the handler mappings of the context that actually dispatches
   *     the requests this resolver will be asked about, and <em>only</em> that context — a
   *     lookup that reaches into a parent context would let one port answer for another's
   *     routes. It is called once, on first use — never eagerly — so a chain may name a context
   *     that does not exist yet when it is built
   */
  public ServletSupportedMethodsResolver(Supplier<Stream<HandlerMapping>> handlerMappings) {
    this.mappings =
        new HandlerMappingLookup<>(handlerMappings, ServletSupportedMethodsResolver::infosOf);
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
   * Resolves what the application serves on the given request's path.
   *
   * @param request the request whose path to look up, never {@code null}
   * @return what the handler mappings say — the path is served with these methods, or by no
   *     handler at all — or empty when they could not be consulted, in which case the request
   *     must be left to the access rules rather than answered from a guess
   */
  public Optional<SupportedMethods> resolve(HttpServletRequest request) {
    try {
      // Everything that can throw belongs inside: the lazy lookup can fail on a request that
      // arrives during context shutdown, and SingletonSupplier does not cache a failure, so it
      // would be retried and would escape on every later request too. LinkageError is caught
      // deliberately: on a servlet application built without Spring MVC the very first touch of
      // a handler-mapping type raises NoClassDefFoundError, which is an Error and would
      // otherwise sail past this and turn every request into a 500.
      var entries = mappings.entries();
      var probe = new ProbeRequest(request);
      ServletRequestPathUtils.parseAndCache(probe);
      for (var entry : entries) {
        SupportedMethods claim = claim(entry, probe);
        if (log.isTraceEnabled()) {
          log.trace("{} ({} infos) on {} {}: {}", entry.mapping().getClass().getSimpleName(),
              entry.infos().size(), request.getMethod(), request.getRequestURI(),
              claim == null ? "no claim" : claim);
        }
        if (claim != null) {
          return Optional.of(claim);
        }
      }
      return Optional.of(SupportedMethods.notServed());
    } catch (Exception | LinkageError ex) {
      // A resolution failure must never turn a request into a server error, nor into a 404 the
      // mappings never said: the access rules answer, as they did before the matrix existed.
      log.debug("Could not resolve the handler mappings; leaving the request to the access rules.",
          ex);
      return Optional.empty();
    }
  }

  /**
   * What one mapping claims for the path: {@code null} when it does not claim it, and the
   * dispatcher would move on to the next; {@link SupportedMethods#notServed()} when it claims
   * the path only to answer {@code 404} itself, which ends the lookup as it would end the
   * dispatch.
   */
  private static SupportedMethods claim(
      HandlerMappingLookup.Entry<HandlerMapping, RequestMappingInfo> entry, ProbeRequest probe)
      throws Exception {
    HandlerMapping mapping = entry.mapping();
    if (mapping instanceof RequestMappingInfoHandlerMapping annotated) {
      SupportedMethods matched = matchInfos(annotated, entry.infos(), probe);
      return matched.pathServed() ? matched : null;
    }
    HandlerExecutionChain chain;
    try {
      chain = mapping.getHandler(probe);
    } catch (HttpRequestMethodNotSupportedException ex) {
      // A mapping that answers "path yes, method no" the way the dispatcher would see it.
      return declaring(ex.getSupportedHttpMethods());
    }
    if (chain == null) {
      return null;
    }
    if (chain.getHandler() instanceof ResourceHttpRequestHandler resources) {
      return resourceClaim(mapping, resources, probe);
    }
    return ANY_METHOD;
  }

  private static SupportedMethods declaring(Collection<HttpMethod> methods) {
    return (methods == null || methods.isEmpty())
        ? ANY_METHOD
        : new SupportedMethods(new LinkedHashSet<>(methods), false);
  }

  /**
   * A resource handler serves the path only when the resource exists — resolved the way the
   * handler itself resolves it, through its own resolvers and locations. Boot's default handler
   * on {@code /**} would otherwise claim every path there is. A miss ends the lookup with
   * "not served": the dispatcher would dispatch to this handler and get its {@code 404}.
   */
  private static SupportedMethods resourceClaim(
      HandlerMapping mapping, ResourceHttpRequestHandler handler, ProbeRequest probe) {
    String pathWithinMapping = pathWithinMapping(mapping, handler, probe);
    if (pathWithinMapping == null) {
      // The handler was matched some way this resolver cannot retrace (a root or default
      // handler, a bean name): let it answer for itself rather than guess a 404.
      return methodsOf(handler);
    }
    String path = ResourceHandlerUtils.normalizeInputPath(pathWithinMapping);
    if (ResourceHandlerUtils.shouldIgnoreInputPath(path)) {
      return SupportedMethods.notServed();
    }
    Resource resource = ResolverChain.of(handler.getResourceResolvers())
        .resolveResource(probe, path, handler.getLocations());
    return resource == null ? SupportedMethods.notServed() : methodsOf(handler);
  }

  private static SupportedMethods methodsOf(ResourceHttpRequestHandler handler) {
    String[] supported = handler.getSupportedMethods();
    if (supported == null) {
      return ANY_METHOD;
    }
    Set<HttpMethod> declared = new LinkedHashSet<>();
    for (String method : supported) {
      declared.add(HttpMethod.valueOf(method));
    }
    return new SupportedMethods(declared, false);
  }

  /**
   * Re-derives the path within the matched pattern, which the mapping only exposes to its
   * interceptors at dispatch time. Same patterns, same comparator, same extraction as the
   * mapping's own lookup.
   */
  // getPathMatcher is deprecated together with the Ant-style matching it is read for; both
  // leave whenever Spring drops that support, and the legacy branch here with them.
  @SuppressWarnings("removal")
  private static String pathWithinMapping(
      HandlerMapping mapping, Object handler, ProbeRequest probe) {
    if (!(mapping instanceof AbstractUrlHandlerMapping urlMapping)) {
      return null;
    }
    if (urlMapping.usesPathPatterns()) {
      PathContainer path =
          ServletRequestPathUtils.getParsedRequestPath(probe).pathWithinApplication();
      return urlMapping.getPathPatternHandlerMap().entrySet().stream()
          .filter(entry -> entry.getValue() == handler && entry.getKey().matches(path))
          .map(Map.Entry::getKey)
          .min(PathPattern.SPECIFICITY_COMPARATOR)
          .map(pattern -> pattern.extractPathWithinPattern(path).value())
          .orElse(null);
    }
    // The mapping cached this lookup path with its own helper while answering getHandler.
    String lookupPath = (String) probe.getAttribute(UrlPathHelper.PATH_ATTRIBUTE);
    if (lookupPath == null) {
      return null;
    }
    PathMatcher matcher = urlMapping.getPathMatcher();
    return urlMapping.getHandlerMap().entrySet().stream()
        .filter(entry -> entry.getValue() == handler && matcher.match(entry.getKey(), lookupPath))
        .map(Map.Entry::getKey)
        .min(matcher.getPatternComparator(lookupPath))
        .map(pattern -> matcher.extractPathWithinPattern(pattern, lookupPath))
        .orElse(null);
  }

  /** What one annotation mapping declares for the request's path. */
  // getUrlPathHelper is deprecated together with the Ant-style matching it is read for; both
  // leave whenever Spring drops that support, and the legacy branch here with them.
  @SuppressWarnings("removal")
  private static SupportedMethods matchInfos(
      RequestMappingInfoHandlerMapping mapping, Collection<RequestMappingInfo> infos,
      ProbeRequest probe) {
    Set<HttpMethod> declared = new LinkedHashSet<>();
    boolean acceptsAnyMethod = false;
    // A mapping still on the deprecated Ant matching resolves through the other path form,
    // whose accessor throws when nothing has populated it. It is prepared with this mapping's
    // own helper, since helpers can differ per mapping and another's would resolve a different
    // path than this mapping dispatches with — and removed again so the next mapping starts
    // clean. A mapping on the default parsed patterns never reads it.
    boolean resolvedHere = !mapping.usesPathPatterns()
        && probe.getAttribute(UrlPathHelper.PATH_ATTRIBUTE) == null;
    if (resolvedHere) {
      mapping.getUrlPathHelper().resolveAndCacheLookupPath(probe);
    }
    try {
      for (RequestMappingInfo info : infos) {
        RequestCondition<?> patterns = info.getActivePatternsCondition();
        if (patterns.getMatchingCondition(probe) == null) {
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
    } finally {
      if (resolvedHere) {
        probe.removeAttribute(UrlPathHelper.PATH_ATTRIBUTE);
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
    public Resource resolveResource(
        HttpServletRequest request, String requestPath, List<? extends Resource> locations) {
      return resolver != null
          ? resolver.resolveResource(request, requestPath, locations, next)
          : null;
    }

    @Override
    public String resolveUrlPath(String resourcePath, List<? extends Resource> locations) {
      return resolver != null ? resolver.resolveUrlPath(resourcePath, locations, next) : null;
    }
  }

  /**
   * The request as the mappings see it: same request line and headers, but attributes of its
   * own, so whatever a mapping caches while answering stays here and the real request reaches
   * the dispatcher untouched. The same device Spring's {@code HandlerMappingIntrospector} uses.
   */
  private static final class ProbeRequest extends HttpServletRequestWrapper {

    /** Package-private on {@code AbstractHandlerMapping}; spelled out here for the same reason. */
    private static final String SUPPRESS_LOGGING_ATTRIBUTE =
        AbstractHandlerMapping.class.getName() + ".SUPPRESS_LOGGING";

    private final Map<String, Object> attributes = new HashMap<>();

    private ProbeRequest(HttpServletRequest request) {
      super(request);
      Enumeration<String> names = request.getAttributeNames();
      while (names.hasMoreElements()) {
        String name = names.nextElement();
        attributes.put(name, request.getAttribute(name));
      }
      // The dispatcher will log "Mapped to" itself; a second line from the probe would mislead.
      attributes.put(SUPPRESS_LOGGING_ATTRIBUTE, Boolean.TRUE);
    }

    @Override
    public Object getAttribute(String name) {
      return attributes.get(name);
    }

    @Override
    public Enumeration<String> getAttributeNames() {
      return Collections.enumeration(attributes.keySet());
    }

    @Override
    public void setAttribute(String name, Object value) {
      attributes.put(name, value);
    }

    @Override
    public void removeAttribute(String name) {
      attributes.remove(name);
    }
  }
}
