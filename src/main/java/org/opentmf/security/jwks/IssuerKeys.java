package org.opentmf.security.jwks;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSetCacheRefreshEvaluator;
import com.nimbusds.jose.jwk.source.JWKSetSource;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.jwk.source.URLBasedJWKSetSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.io.IOException;
import java.net.Proxy;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.UnaryOperator;
import lombok.extern.slf4j.Slf4j;
import org.opentmf.security.model.JwksProperties;
import org.springframework.core.io.Resource;

/**
 * The signing keys of one trusted issuer, cache-first: fetched once at warm-up, refreshed in
 * the background ahead of expiry, served stale while refreshes fail (bounded by the outage
 * TTL), refreshed on an unknown key id at most twice per interval — and never fetched on a
 * request thread once a first load has succeeded. Both stacks read their keys through this.
 *
 * <p>Built on Nimbus's own {@link JWKSourceBuilder} composition, innermost to outermost: the
 * URL source (through {@link JwkSetRetriever}) → outage tolerance → rate limiting →
 * refresh-ahead caching. Nimbus's immediate retry is deliberately off: it would let a cold
 * fetch block a request thread twice the timeouts, and the scheduled refresh plus the next
 * request are the retry. The library adds one thing below all of it: a record of whether
 * <em>any</em> load ever succeeded, which is what tells a rate-limited miss apart — an unknown
 * key id when the keys are known, an outage when they never were.
 *
 * @author Gokhan Demir
 */
@Slf4j
public class IssuerKeys {

  private static final int DEFAULT_TIMEOUT_MILLIS = 30_000;

  private final String name;
  private final JWKSource<SecurityContext> source;
  private final AtomicBoolean everLoaded = new AtomicBoolean();
  private final Duration retryAfter;
  private final boolean remote;

  /**
   * Creates the key source of one issuer.
   *
   * @param name the issuer's configured name — the only identity used in logs and error bodies
   * @param jwkSetUri where the keys come from: an http(s) URL to fetch, or any other resource
   * @param proxy the configured {@code host:port} override, or {@code null}
   * @param properties the fetch and cache settings
   * @param environment reads a process environment variable, {@code null} when absent
   */
  public IssuerKeys(
      String name, Resource jwkSetUri, String proxy, JwksProperties properties,
      UnaryOperator<String> environment) {
    this.name = name;
    this.retryAfter = properties.getRefreshInterval();
    URL url = urlOf(name, jwkSetUri);
    boolean fetched = "http".equals(url.getProtocol()) || "https".equals(url.getProtocol());
    JwkSetRetriever retriever = new JwkSetRetriever(
        jwkSetUri, url, fetched ? proxyFor(url, proxy, environment) : Proxy.NO_PROXY,
        timeout(properties.getConnectTimeout(), "sun.net.client.defaultConnectTimeout"),
        timeout(properties.getReadTimeout(), "sun.net.client.defaultReadTimeout"));
    this.remote = retriever.isRemote();
    JWKSetSource<SecurityContext> loads =
        new LoadTracking(new URLBasedJWKSetSource<>(url, retriever));
    // Nimbus's refresh-ahead time and refresh timeout must fit inside the TTL together; they
    // keep their defaults for any TTL that has room for them and scale down for a short one.
    long ttl = properties.getCacheTtl().toMillis();
    long refreshTimeout = Math.min(JWKSourceBuilder.DEFAULT_CACHE_REFRESH_TIMEOUT, ttl / 3);
    long refreshAhead = Math.min(JWKSourceBuilder.DEFAULT_REFRESH_AHEAD_TIME, ttl / 3);
    try {
      this.source = JWKSourceBuilder.create(loads)
          .retrying(false)
          .outageTolerant(properties.getOutageTtl().toMillis())
          .rateLimited(properties.getRefreshInterval().toMillis())
          .cache(ttl, refreshTimeout)
          .refreshAheadCache(refreshAhead, true)
          .build();
    } catch (IllegalStateException | IllegalArgumentException e) {
      throw new IllegalArgumentException(
          "Invalid opentmf.security.jwks settings for issuer '" + name + "': " + e.getMessage(), e);
    }
  }

  /** The issuer's configured name. */
  public String name() {
    return name;
  }

  /** The keys, for the decoders: Nimbus's composed source, with the library's load record. */
  public JWKSource<SecurityContext> source() {
    return source;
  }

  /** Whether any load ever succeeded; set on the first success at the URL level, never reset. */
  public boolean everLoaded() {
    return everLoaded.get();
  }

  /** The interval a {@code 503} tells the caller to wait before retrying. */
  public Duration retryAfter() {
    return retryAfter;
  }

  /** Whether the keys are fetched over the network, as opposed to read from a local resource. */
  public boolean remote() {
    return remote;
  }

  /**
   * Performs the first load now, off the request path, and says how it went — by the issuer's
   * name, never its URL. A failure here is not final: the next request or the next scheduled
   * refresh tries again.
   *
   * @return {@code true} when the keys are available after this call
   */
  public boolean warmUp() {
    try {
      List<JWK> keys = source.get(new JWKSelector(new JWKMatcher.Builder().build()), null);
      log.info("Signing keys of issuer '{}' loaded ({} keys).", name, keys.size());
      return true;
    } catch (KeySourceException | RuntimeException ex) {
      log.warn("Signing keys of issuer '{}' could not be loaded: {}: {}. Bearer tokens from this"
              + " issuer answer 503 until a refresh succeeds.",
          name, ex.getClass().getSimpleName(), ex.getMessage());
      log.debug("Signing keys of issuer '{}' could not be loaded.", name, ex);
      return false;
    }
  }

  private static URL urlOf(String name, Resource jwkSetUri) {
    try {
      return jwkSetUri.getURL();
    } catch (IOException e) {
      throw new IllegalArgumentException(
          "The jwk-set-uri of issuer '" + name + "' is not a resolvable resource", e);
    }
  }

  private static Proxy proxyFor(URL url, String proxy, UnaryOperator<String> environment) {
    try {
      return ProxyResolver.resolve(url.toURI(), proxy, environment);
    } catch (URISyntaxException e) {
      return Proxy.NO_PROXY;
    }
  }

  /** The configured value, else the JVM property the pre-3.2.0 fetch honoured, else 30 s. */
  private static Duration timeout(Duration configured, String jvmProperty) {
    if (configured != null) {
      return configured;
    }
    return Duration.ofMillis(Integer.getInteger(jvmProperty, DEFAULT_TIMEOUT_MILLIS));
  }

  /** Records the first successful load; sits below every Nimbus layer so nothing else counts. */
  private final class LoadTracking implements JWKSetSource<SecurityContext> {

    private final JWKSetSource<SecurityContext> delegate;

    private LoadTracking(JWKSetSource<SecurityContext> delegate) {
      this.delegate = delegate;
    }

    @Override
    public JWKSet getJWKSet(
        JWKSetCacheRefreshEvaluator refreshEvaluator, long currentTime, SecurityContext context)
        throws KeySourceException {
      JWKSet loaded = delegate.getJWKSet(refreshEvaluator, currentTime, context);
      everLoaded.set(true);
      return loaded;
    }

    @Override
    public void close() throws IOException {
      delegate.close();
    }
  }
}
