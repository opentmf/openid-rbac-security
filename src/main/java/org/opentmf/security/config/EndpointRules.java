package org.opentmf.security.config;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;
import org.opentmf.security.model.Endpoint;
import org.opentmf.security.model.EndpointMethod;
import org.springframework.http.HttpMethod;
import org.springframework.util.StringUtils;

/**
 * Shared translation between the configured access rules and the HTTP methods they cover.
 *
 * @author Gokhan Demir
 */
public final class EndpointRules {

  /**
   * What Spring answers on {@code OPTIONS} for a mapping that names no method: every method
   * except {@code TRACE}, in declaration order. Constant, so built once — this sits on the
   * denial path, which a caller controls the traffic on.
   */
  private static final Set<HttpMethod> ANY_METHOD_OPTIONS_ALLOW =
      Arrays.stream(HttpMethod.values())
          .filter(method -> !HttpMethod.TRACE.equals(method))
          .collect(Collectors.collectingAndThen(
              Collectors.toCollection(LinkedHashSet::new), Collections::unmodifiableSet));

  private EndpointRules() {
    // Utility class.
  }

  /**
   * Returns the HTTP methods an access rule covers. A {@link EndpointMethod#GET} rule covers
   * {@code HEAD} as well, because Spring MVC and WebFlux both serve {@code HEAD} from the
   * handler mapped to {@code GET}; without this the framework would answer a {@code HEAD}
   * request that the security chain had already refused.
   *
   * @param endpoint the configured rule, never {@code null}
   * @return the methods to register the rule for, in registration order
   */
  public static HttpMethod[] httpMethodsFor(Endpoint endpoint) {
    HttpMethod method = endpoint.getMethod().toHttpMethod();
    return HttpMethod.GET.equals(method)
        ? new HttpMethod[] {HttpMethod.GET, HttpMethod.HEAD}
        : new HttpMethod[] {method};
  }

  /**
   * The HTTP-status matrix, decided for one request from what the application's handler
   * mappings say about its path — before authentication and before the access rules, which
   * only ever see a request that lands on {@link MatrixAnswer.Kind#PROCEED}:
   *
   * <ol>
   *   <li>no handler serves the path → {@code 404}, anonymous or authenticated;</li>
   *   <li>the path is served but the method is not implemented on it — unknown method names
   *       included → {@code 405}, with no {@code Allow} header;</li>
   *   <li>a plain {@code OPTIONS} on a served path → {@code 200} with the {@code Allow} Spring's
   *       own {@code HttpOptionsHandler} would send, unless the application maps
   *       {@code OPTIONS} itself, in which case it has an answer of its own to give;</li>
   *   <li>otherwise the request proceeds, and no token or an invalid one answers {@code 401},
   *       a valid token without the role {@code 403}.</li>
   * </ol>
   *
   * <p>Stack-neutral on purpose: servlet and reactive must answer the same request the same way,
   * and a copy per stack would let them drift apart one fix at a time.
   *
   * @param requestMethod the method the caller used, never {@code null}
   * @param supported what the application's handler mappings say about the path
   * @return the row of the matrix the request lands on
   */
  public static MatrixAnswer answerFor(HttpMethod requestMethod, SupportedMethods supported) {
    if (!supported.pathServed()) {
      return MatrixAnswer.notFound();
    }
    Set<HttpMethod> declared = supported.declared();
    if (HttpMethod.OPTIONS.equals(requestMethod)) {
      return declared.contains(HttpMethod.OPTIONS)
          ? MatrixAnswer.proceed()
          : MatrixAnswer.options(optionsAllow(declared));
    }
    if (supported.acceptsAnyMethod() || serves(declared, requestMethod)) {
      return MatrixAnswer.proceed();
    }
    return MatrixAnswer.methodNotAllowed();
  }

  /**
   * Mirrors Spring's own method matching, where a {@code HEAD} request is served by the handler
   * mapped to {@code GET}.
   */
  private static boolean serves(Set<HttpMethod> declared, HttpMethod method) {
    return declared.contains(method)
        || (HttpMethod.HEAD.equals(method) && declared.contains(HttpMethod.GET));
  }

  /**
   * Builds the {@code Allow} header value for an {@code OPTIONS} response, reproducing
   * Spring's own {@code HttpOptionsHandler}: the declared methods, plus {@code HEAD} when
   * {@code GET} is declared, plus {@code OPTIONS} itself. When nothing is declared — a
   * mapping that names no method accepts them all — Spring answers with every method except
   * {@code TRACE}, and so do we.
   *
   * @param declared the methods the application declares on the path, never {@code null}
   * @return the methods to advertise, never empty
   */
  public static Set<HttpMethod> optionsAllow(Set<HttpMethod> declared) {
    if (declared.isEmpty()) {
      return ANY_METHOD_OPTIONS_ALLOW;
    }
    Set<HttpMethod> allowed = new LinkedHashSet<>();
    for (HttpMethod method : declared) {
      allowed.add(method);
      if (HttpMethod.GET.equals(method)) {
        // HEAD goes right after GET — where Spring's HttpOptionsHandler puts it, and where the
        // library's canonical order (see SupportedMethods) already has it for resolver-supplied
        // sets; doing it here too keeps directly-built sets consistent.
        allowed.add(HttpMethod.HEAD);
      }
    }
    allowed.add(HttpMethod.OPTIONS);
    return allowed;
  }

  /**
   * Renders the {@code Allow} value for an {@code OPTIONS} response, the way Spring renders its
   * own: {@code HttpOptionsHandler} goes through {@code HttpHeaders.setAllow}, which joins with
   * a bare {@code ","}.
   *
   * <p>The <em>order</em> of the methods is the library's own canonical one (see
   * {@code SupportedMethods}): Spring's ordering follows its registry's per-JVM-salted iteration
   * and a mapping's declaration order, neither of which is reproducible from outside, so the
   * library trades exact byte-parity of the ordering for one that is deterministic run after run.
   *
   * @param methods the methods to advertise, never {@code null}
   * @return the header value
   */
  public static String optionsAllowHeader(Set<HttpMethod> methods) {
    return StringUtils.collectionToCommaDelimitedString(methods);
  }
}
