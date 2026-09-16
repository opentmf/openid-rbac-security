package org.opentmf.security.jwks;

import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.Resource;
import com.nimbusds.jose.util.ResourceRetriever;
import java.io.IOException;
import java.io.InputStream;
import java.net.Proxy;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import org.springframework.http.MediaType;

/**
 * Fetches one issuer's JWK set: over HTTP(S) through the resolved proxy with explicit timeouts,
 * or — for anything that is not a URL to fetch ({@code classpath:}, {@code file:}, a resource
 * inside a jar) — straight from the Spring resource's stream, with no network at all. Nimbus's
 * own retriever does the HTTP part, so redirects, size limits and content handling are its
 * standard ones; only the proxy and the timeouts are the library's.
 *
 * @author Gokhan Demir
 */
final class JwkSetRetriever implements ResourceRetriever {

  private final org.springframework.core.io.Resource resource;
  private final boolean remote;
  private final DefaultResourceRetriever http;

  JwkSetRetriever(
      org.springframework.core.io.Resource resource, URL url, Proxy proxy,
      Duration connectTimeout, Duration readTimeout) {
    this.resource = resource;
    String protocol = url.getProtocol();
    this.remote = "http".equals(protocol) || "https".equals(protocol);
    this.http = new DefaultResourceRetriever(
        (int) connectTimeout.toMillis(), (int) readTimeout.toMillis());
    this.http.setProxy(proxy == Proxy.NO_PROXY ? null : proxy);
  }

  boolean isRemote() {
    return remote;
  }

  @Override
  public Resource retrieveResource(URL url) throws IOException {
    if (remote) {
      return http.retrieveResource(url);
    }
    try (InputStream in = resource.getInputStream()) {
      return new Resource(
          new String(in.readAllBytes(), StandardCharsets.UTF_8), MediaType.APPLICATION_JSON_VALUE);
    }
  }
}
