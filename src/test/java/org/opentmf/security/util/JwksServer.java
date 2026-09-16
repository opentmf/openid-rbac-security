package org.opentmf.security.util;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * A scriptable JWKS endpoint on localhost: serves whatever JWK set it is told to, can be made
 * to fail, counts every fetch, and records the request lines it saw — so a test can prove a
 * fetch happened, or did not, or came through a proxy.
 *
 * @author Gokhan Demir
 */
public final class JwksServer implements AutoCloseable {

  public static final String PATH = "/certs";

  private final HttpServer server;
  private final AtomicReference<String> jwkSet = new AtomicReference<>("{\"keys\":[]}");
  private final AtomicInteger status = new AtomicInteger(200);
  private final AtomicInteger fetches = new AtomicInteger();
  private final List<String> requestLines = Collections.synchronizedList(new ArrayList<>());

  private JwksServer(HttpServer server) {
    this.server = server;
  }

  public static JwksServer start(String jwkSetJson) {
    try {
      HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
      JwksServer jwks = new JwksServer(server);
      jwks.jwkSet.set(jwkSetJson);
      server.createContext(PATH, exchange -> {
        jwks.fetches.incrementAndGet();
        jwks.requestLines.add(exchange.getRequestMethod() + " " + exchange.getRequestURI()
            + " host=" + exchange.getRequestHeaders().getFirst("Host"));
        int code = jwks.status.get();
        byte[] body = code == 200
            ? jwks.jwkSet.get().getBytes(StandardCharsets.UTF_8)
            : new byte[0];
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(code, body.length == 0 ? -1 : body.length);
        try (OutputStream out = exchange.getResponseBody()) {
          out.write(body);
        }
      });
      server.start();
      return jwks;
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  public String url() {
    return "http://127.0.0.1:" + server.getAddress().getPort() + PATH;
  }

  public int port() {
    return server.getAddress().getPort();
  }

  /** What the next fetches receive. */
  public void serve(String jwkSetJson) {
    jwkSet.set(jwkSetJson);
    status.set(200);
  }

  /** Every fetch fails with the given status until {@link #serve} is called again. */
  public void fail(int httpStatus) {
    status.set(httpStatus);
  }

  public int fetches() {
    return fetches.get();
  }

  public List<String> requestLines() {
    return List.copyOf(requestLines);
  }

  @Override
  public void close() {
    server.stop(0);
  }
}
