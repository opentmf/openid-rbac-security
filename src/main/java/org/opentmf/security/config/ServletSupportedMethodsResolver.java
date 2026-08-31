package org.opentmf.security.config;

import jakarta.servlet.http.HttpServletRequest;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Stream;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
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
 * <p>The handler-mapping <em>beans</em> are looked up once, lazily, on first use — never while
 * the security filter chain is being built, which would force Spring MVC's infrastructure to
 * initialize too early. Their mappings are read through a briefly cached view (at most one
 * second stale — see {@link HandlerMappingLookup}), so a consumer that registers or removes
 * mappings at runtime ({@code registerMapping}, a refreshed scope) is answered from what the
 * application serves now, not from a startup snapshot.
 *
 * <p>Only annotation-based handler mappings contribute. Functional routes, resource handlers
 * and any other {@code HandlerMapping} are invisible here, so a path served only that way is
 * reported as not served, and the caller leaves the denial as it stands.
 *
 * @author Gokhan Demir
 */
@Slf4j
public class ServletSupportedMethodsResolver {

  private final HandlerMappingLookup<RequestMappingInfoHandlerMapping, RequestMappingInfo>
      mappings;

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
    this.mappings =
        new HandlerMappingLookup<>(handlerMappings, mapping -> mapping.getHandlerMethods().keySet());
  }

  /** Primes the lazy handler-mapping lookup off the request path; failures retry on first use. */
  public void warmUp() {
    mappings.warmUp();
  }

  /**
   * Resolves the methods the application serves on the given request's path.
   *
   * @param request the request whose path to look up, never {@code null}
   * @return what the handler mappings declare, never {@code null}
   */
  public SupportedMethods resolve(HttpServletRequest request) {
    boolean parsedHere = false;
    try {
      // Everything that can throw belongs inside: the lazy lookup can fail on a denial that
      // arrives during context shutdown, and SingletonSupplier does not cache a failure, so it
      // would be retried and would escape on every later denial too. LinkageError is caught
      // deliberately: on a servlet application built without Spring MVC the very first touch of
      // a handler-mapping type raises NoClassDefFoundError, which is an Error and would
      // otherwise sail past this and turn every denial into a 500.
      var entries = mappings.entries();
      if (entries.isEmpty()) {
        return SupportedMethods.notServed();
      }
      parsedHere = !ServletRequestPathUtils.hasParsedRequestPath(request);
      if (parsedHere) {
        ServletRequestPathUtils.parseAndCache(request);
      }
      return match(entries, request);
    } catch (RuntimeException | LinkageError ex) {
      // A resolution failure must never turn a denial into a server error.
      log.debug("Could not resolve supported methods; leaving the denial as it is.", ex);
      return SupportedMethods.notServed();
    } finally {
      if (parsedHere) {
        ServletRequestPathUtils.clearParsedRequestPath(request);
      }
    }
  }

  private static SupportedMethods match(
      List<HandlerMappingLookup.Entry<RequestMappingInfoHandlerMapping, RequestMappingInfo>>
          entries,
      HttpServletRequest request) {
    Set<HttpMethod> declared = new LinkedHashSet<>();
    boolean acceptsAnyMethod = false;
    for (var entry : entries) {
      SupportedMethods one = matchOneMapping(entry, request);
      declared.addAll(one.declared());
      acceptsAnyMethod = acceptsAnyMethod || one.acceptsAnyMethod();
    }
    return new SupportedMethods(declared, acceptsAnyMethod);
  }

  /** What one mapping declares for the request's path. Pure: merging is the caller's job. */
  // getUrlPathHelper is deprecated together with the Ant-style matching it is read for; both
  // leave whenever Spring drops that support, and the legacy branch here with them.
  @SuppressWarnings("removal")
  private static SupportedMethods matchOneMapping(
      HandlerMappingLookup.Entry<RequestMappingInfoHandlerMapping, RequestMappingInfo> entry,
      HttpServletRequest request) {
    Set<HttpMethod> declared = new LinkedHashSet<>();
    boolean acceptsAnyMethod = false;
    // A mapping still on the deprecated Ant matching resolves through the other path form,
    // whose accessor throws when the DispatcherServlet has not populated it — which it never
    // has out here in the filter chain. It is prepared with this mapping's own helper, since
    // helpers can differ per mapping and another's would resolve a different path than this
    // mapping dispatches with. A mapping on the default parsed patterns never reads it, so
    // nothing is prepared for one.
    boolean resolvedHere = !entry.mapping().usesPathPatterns()
        && request.getAttribute(UrlPathHelper.PATH_ATTRIBUTE) == null;
    if (resolvedHere) {
      entry.mapping().getUrlPathHelper().resolveAndCacheLookupPath(request);
    }
    try {
      for (RequestMappingInfo info : entry.infos()) {
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
    } finally {
      if (resolvedHere) {
        request.removeAttribute(UrlPathHelper.PATH_ATTRIBUTE);
      }
    }
    return new SupportedMethods(declared, acceptsAnyMethod);
  }
}
