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
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.UnaryOperator;
import java.util.regex.Pattern;
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
  private final AtomicReference<Snapshot> snapshot = new AtomicReference<>(Snapshot.NONE);
  private final AtomicBoolean probing = new AtomicBoolean();
  private final Duration retryAfter;
  private final boolean remote;
  private final String origin;
  private final String route;
  private final Duration freshFor;
  private final Duration outageTtl;

  /** What the keys are in: their state as the wire would answer, and how they got there. */
  public enum State {
    /** A set is loaded and younger than the cache horizon: today's answers. */
    FRESH,
    /** A set is loaded, older than the cache horizon, younger than the outage TTL: still served. */
    STALE,
    /** Never loaded, or older than the outage TTL: every bearer request answers {@code 503}. */
    UNAVAILABLE
  }

  /**
   * What the last loads left behind.
   *
   * @param loadedAt when the last successful load happened, {@code null} before the first
   * @param keys the number of keys in the last loaded set
   * @param failures how many loads failed
   * @param lastFailure the last failed load's class and message, {@code null} when none failed
   * @param failedAt when the last failed load happened, {@code null} when none failed
   */
  public record Snapshot(
      Instant loadedAt, int keys, long failures, String lastFailure, Instant failedAt) {

    static final Snapshot NONE = new Snapshot(null, 0, 0, null, null);

    Snapshot loaded(Instant at, int count) {
      return new Snapshot(at, count, failures, lastFailure, failedAt);
    }

    Snapshot failed(Instant at, Throwable cause) {
      return new Snapshot(loadedAt, keys, failures + 1, describe(cause), at);
    }
  }

  private static final Pattern URL = Pattern.compile("https?://([^/\\s:]+)[^\\s]*");

  /**
   * The failure as class and message, with every URL in the message reduced to its host — Nimbus
   * quotes the full JWKS URL, and neither a log line nor a health detail may carry a path.
   */
  static String describe(Throwable cause) {
    String message = cause.getMessage() == null ? "" : cause.getMessage();
    return cause.getClass().getSimpleName() + ": " + URL.matcher(message).replaceAll("$1");
  }

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
    this.outageTtl = properties.getOutageTtl();
    URL url = urlOf(name, jwkSetUri);
    boolean fetched = "http".equals(url.getProtocol()) || "https".equals(url.getProtocol());
    Proxy viaProxy = fetched ? proxyFor(url, proxy, environment) : Proxy.NO_PROXY;
    // The host, never the path: what an operator needs to read at boot, nothing a body may leak.
    this.origin = fetched ? url.getHost() : url.getProtocol() + ":";
    this.route = viaProxy == Proxy.NO_PROXY ? "direct" : "via proxy " + viaProxy.address();
    JwkSetRetriever retriever = new JwkSetRetriever(
        jwkSetUri, url, viaProxy,
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
    this.freshFor = Duration.ofMillis(ttl + refreshTimeout);
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

  /** The JWKS host (or the local resource's scheme) — for logs and health details, never bodies. */
  public String origin() {
    return origin;
  }

  /** What the last loads left behind; see {@link Snapshot}. */
  public Snapshot snapshot() {
    return snapshot.get();
  }

  /** The state the wire answers from, at the given instant; see {@link State}. */
  public State state(Instant now) {
    Snapshot current = snapshot.get();
    if (current.loadedAt() == null) {
      return State.UNAVAILABLE;
    }
    Duration age = Duration.between(current.loadedAt(), now);
    if (age.compareTo(freshFor) <= 0) {
      return State.FRESH;
    }
    return age.compareTo(outageTtl) <= 0 ? State.STALE : State.UNAVAILABLE;
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
      log.info("Signing keys of issuer '{}' loaded ({} keys) from {} ({}).",
          name, keys.size(), origin, route);
      return true;
    } catch (KeySourceException | RuntimeException ex) {
      log.warn("Signing keys of issuer '{}' could not be loaded from {} ({}): {}. Bearer tokens"
              + " from this issuer answer 503 until a refresh succeeds.",
          name, origin, route, describe(ex));
      log.debug("Signing keys of issuer '{}' could not be loaded.", name, ex);
      return false;
    }
  }

  /**
   * Retries the first load in the background when the keys are unavailable, at most one attempt
   * in flight, paced by the rate limiter below it. A readiness probe that finds the keys
   * unavailable calls this, so Kubernetes's probing becomes the retry driver of a cold outage
   * instead of the next bearer request — and the probe itself never waits on the network.
   */
  public void retryInBackground() {
    if (!probing.compareAndSet(false, true)) {
      return;
    }
    Thread thread = new Thread(() -> {
      try {
        warmUp();
      } finally {
        probing.set(false);
      }
    }, "jwks-retry-" + name);
    thread.setDaemon(true);
    thread.start();
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
      JWKSet loaded;
      try {
        loaded = delegate.getJWKSet(refreshEvaluator, currentTime, context);
      } catch (KeySourceException | RuntimeException ex) {
        snapshot.updateAndGet(current -> current.failed(Instant.now(), ex));
        throw ex;
      }
      everLoaded.set(true);
      snapshot.updateAndGet(current -> current.loaded(Instant.now(), loaded.getKeys().size()));
      return loaded;
    }

    @Override
    public void close() throws IOException {
      delegate.close();
    }
  }
}
