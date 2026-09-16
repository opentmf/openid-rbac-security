package org.opentmf.security.jwks;

import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.URI;
import java.util.List;
import java.util.Locale;
import java.util.function.UnaryOperator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

/**
 * Decides the proxy a JWK-set fetch goes through, in the order every other egress in the
 * estate is resolved:
 *
 * <ol>
 *   <li>the per-issuer {@code proxy} property, when set;</li>
 *   <li>the JVM's standard proxy properties ({@code https.proxyHost}, {@code http.proxyHost},
 *       {@code http.nonProxyHosts}), through the JVM's default {@link ProxySelector} — exactly
 *       what the fetch honoured before 3.2.0;</li>
 *   <li>the process environment: {@code HTTPS_PROXY} (or {@code HTTP_PROXY} for a plain
 *       {@code http:} URL), with {@code NO_PROXY} exclusions — upper- and lower-case, as the
 *       JDK never reads these on its own;</li>
 *   <li>a direct connection.</li>
 * </ol>
 *
 * @author Gokhan Demir
 */
@Slf4j
final class ProxyResolver {

  private ProxyResolver() {
    // Static resolution.
  }

  /**
   * Resolves the proxy for the given URL.
   *
   * @param uri the JWK-set URL, never {@code null}
   * @param override the configured {@code host:port}, or {@code null}
   * @param environment reads a process environment variable, {@code null} when absent
   * @return the proxy, or {@link Proxy#NO_PROXY} for a direct connection
   */
  static Proxy resolve(URI uri, String override, UnaryOperator<String> environment) {
    if (StringUtils.hasText(override)) {
      return parse(override, "the issuer's proxy property");
    }
    Proxy fromJvm = fromJvmProperties(uri);
    if (fromJvm != null) {
      return fromJvm;
    }
    return fromEnvironment(uri, environment);
  }

  private static Proxy fromJvmProperties(URI uri) {
    List<Proxy> selected = ProxySelector.getDefault().select(uri);
    for (Proxy proxy : selected) {
      if (proxy.type() == Proxy.Type.HTTP) {
        return proxy;
      }
    }
    return null;
  }

  private static Proxy fromEnvironment(URI uri, UnaryOperator<String> environment) {
    String host = uri.getHost();
    if (host == null || excluded(host, firstOf(environment, "NO_PROXY", "no_proxy"))) {
      return Proxy.NO_PROXY;
    }
    boolean https = "https".equalsIgnoreCase(uri.getScheme());
    String configured = https
        ? firstOf(environment, "HTTPS_PROXY", "https_proxy")
        : firstOf(environment, "HTTP_PROXY", "http_proxy");
    if (!StringUtils.hasText(configured)) {
      return Proxy.NO_PROXY;
    }
    return parse(configured, https ? "HTTPS_PROXY" : "HTTP_PROXY");
  }

  private static String firstOf(UnaryOperator<String> environment, String... names) {
    for (String name : names) {
      String value = environment.apply(name);
      if (StringUtils.hasText(value)) {
        return value;
      }
    }
    return null;
  }

  /** {@code NO_PROXY} semantics: exact host, or a domain suffix with or without a leading dot. */
  private static boolean excluded(String host, String noProxy) {
    if (!StringUtils.hasText(noProxy)) {
      return false;
    }
    String lowerHost = host.toLowerCase(Locale.ROOT);
    for (String entry : noProxy.split(",")) {
      String pattern = entry.trim().toLowerCase(Locale.ROOT);
      if (pattern.isEmpty()) {
        continue;
      }
      if ("*".equals(pattern) || lowerHost.equals(pattern)) {
        return true;
      }
      String suffix = pattern.startsWith(".") ? pattern : "." + pattern;
      if (lowerHost.endsWith(suffix)) {
        return true;
      }
    }
    return false;
  }

  /** Accepts {@code host:port} and {@code http://host:port}; anything else is a named error. */
  private static Proxy parse(String value, String origin) {
    String spec = value.trim();
    String authority = spec.contains("://") ? URI.create(spec).getAuthority() : spec;
    if (authority == null) {
      throw new IllegalArgumentException("Cannot read a proxy from " + origin + ": '" + value + "'");
    }
    int colon = authority.lastIndexOf(':');
    if (colon <= 0 || colon == authority.length() - 1) {
      throw new IllegalArgumentException(
          "A proxy must be host:port; " + origin + " is '" + value + "'");
    }
    String host = authority.substring(0, colon);
    int port;
    try {
      port = Integer.parseInt(authority.substring(colon + 1));
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException(
          "A proxy must be host:port; " + origin + " is '" + value + "'", e);
    }
    return new Proxy(Proxy.Type.HTTP, InetSocketAddress.createUnresolved(host, port));
  }
}
