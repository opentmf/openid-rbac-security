package org.opentmf.security.config;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Stream;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.util.function.SingletonSupplier;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.mvc.condition.RequestCondition;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.RequestMappingInfoHandlerMapping;
import org.springframework.web.util.ServletRequestPathUtils;
import org.springframework.web.util.UrlPathHelper;

/**
 * Answers what HTTP methods the application actually serves on a given request path, by
 * consulting the same {@code RequestMappingInfo} objects Spring MVC dispatches with.
 *
 * <p>The handler mappings are read once, lazily, on first use — never while the security
 * filter chain is being built, which would force Spring MVC's infrastructure to initialize
 * too early. Mappings registered after that point are not reflected; nothing in these
 * services registers mappings at runtime.
 *
 * <p>Only annotation-based handler mappings contribute. Functional routes, resource handlers
 * and any other {@code HandlerMapping} are invisible here, so a path served only that way is
 * reported as not served, and the caller leaves the denial as it stands.
 *
 * @author Gokhan Demir
 */
@Slf4j
public class ServletSupportedMethodsResolver {

  private final Supplier<Snapshot> snapshot;

  /** What one read of the handler mappings yielded, kept for the life of the resolver. */
  private record Snapshot(Set<RequestMappingInfo> infos, UrlPathHelper pathHelper) {}

  /**
   * Creates a resolver over the given handler mappings.
   *
   * @param handlerMappings supplies the handler mappings of the context that actually dispatches
   *     the requests this resolver will be asked about, and <em>only</em> that context — a
   *     lookup that reaches into a parent context would let one port answer for another's
   *     routes. It is called once, on first use — never eagerly — so a chain may name a context
   *     that does not exist yet when it is built
   */
  public ServletSupportedMethodsResolver(
      Supplier<Stream<RequestMappingInfoHandlerMapping>> handlerMappings) {
    this.snapshot = SingletonSupplier.of(() -> snapshot(handlerMappings));
  }

  // getUrlPathHelper is deprecated together with the Ant-style matching it is read for; both
  // leave whenever Spring drops that support, and the legacy branch of resolve() with them.
  @SuppressWarnings("removal")
  private static Snapshot snapshot(
      Supplier<Stream<RequestMappingInfoHandlerMapping>> handlerMappings) {
    List<RequestMappingInfoHandlerMapping> mappings = handlerMappings.get().toList();
    // Registration order, kept: the Allow header must name methods in the same order run after
    // run — and in the order Spring's own 405 would — not in the salted iteration order an
    // unordered set happens to have in this JVM.
    Set<RequestMappingInfo> infos = new LinkedHashSet<>();
    mappings.forEach(mapping -> infos.addAll(mapping.getHandlerMethods().keySet()));
    // A mapping still on the deprecated Ant matching resolves its lookup path with the helper
    // the application configured, which need not be the default one. Matching here with a
    // different helper than the DispatcherServlet uses would answer for different paths than
    // the application actually serves.
    UrlPathHelper pathHelper = mappings.isEmpty()
        ? UrlPathHelper.defaultInstance
        : mappings.get(0).getUrlPathHelper();
    log.debug("Captured {} request mappings for HTTP method resolution.", infos.size());
    return new Snapshot(Collections.unmodifiableSet(infos), pathHelper);
  }

  /**
   * Resolves the methods the application serves on the given request's path.
   *
   * @param request the request whose path to look up, never {@code null}
   * @return what the handler mappings declare, never {@code null}
   */
  public SupportedMethods resolve(HttpServletRequest request) {
    boolean parsedHere = false;
    boolean resolvedHere = false;
    try {
      // Everything that can throw belongs inside: the lazy snapshot can fail on a denial that
      // arrives during context shutdown, and SingletonSupplier does not cache a failure, so it
      // would be retried and would escape on every later denial too.
      Snapshot captured = snapshot.get();
      if (captured.infos().isEmpty()) {
        return SupportedMethods.notServed();
      }
      parsedHere = !ServletRequestPathUtils.hasParsedRequestPath(request);
      if (parsedHere) {
        ServletRequestPathUtils.parseAndCache(request);
      }
      // A mapping still on the deprecated Ant matching resolves through the other path form,
      // whose accessor throws when the DispatcherServlet has not populated it — which it never
      // has out here in the filter chain. Preparing both means such an application gets the
      // feature rather than an exception per mapping, swallowed, and no 405 ever.
      resolvedHere = request.getAttribute(UrlPathHelper.PATH_ATTRIBUTE) == null;
      if (resolvedHere) {
        captured.pathHelper().resolveAndCacheLookupPath(request);
      }
      return match(captured.infos(), request);
    } catch (RuntimeException | LinkageError ex) {
      // A resolution failure must never turn a denial into a server error. LinkageError is in
      // the list deliberately: on a servlet application built without Spring MVC the very first
      // touch of a handler-mapping type raises NoClassDefFoundError, which is an Error and would
      // otherwise sail past this and turn every denial into a 500.
      log.debug("Could not resolve supported methods; leaving the denial as it is.", ex);
      return SupportedMethods.notServed();
    } finally {
      if (resolvedHere) {
        request.removeAttribute(UrlPathHelper.PATH_ATTRIBUTE);
      }
      if (parsedHere) {
        ServletRequestPathUtils.clearParsedRequestPath(request);
      }
    }
  }

  private static SupportedMethods match(
      Set<RequestMappingInfo> infos, HttpServletRequest request) {
    Set<HttpMethod> declared = new LinkedHashSet<>();
    boolean acceptsAnyMethod = false;
    for (RequestMappingInfo info : infos) {
      RequestCondition<?> patterns = info.getActivePatternsCondition();
      if (patterns.getMatchingCondition(request) == null) {
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
}
