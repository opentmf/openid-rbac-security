package org.opentmf.security.util;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * A minimal HTTP forward proxy on localhost: accepts a request whose request-target is an
 * absolute URI (what a client sends to a proxy), fetches it directly, relays the answer, and
 * records what it was asked for — so a test can prove a JWKS fetch went through the proxy.
 *
 * @author Gokhan Demir
 */
public final class ForwardProxy implements AutoCloseable {

  private final HttpServer server;
  private final List<String> forwarded = Collections.synchronizedList(new ArrayList<>());

  private ForwardProxy(HttpServer server) {
    this.server = server;
  }

  public static ForwardProxy start() {
    try {
      HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
      ForwardProxy proxy = new ForwardProxy(server);
      server.createContext("/", exchange -> {
        URI target = exchange.getRequestURI();
        proxy.forwarded.add(exchange.getRequestMethod() + " " + target);
        if (!target.isAbsolute()) {
          exchange.sendResponseHeaders(400, -1);
          exchange.close();
          return;
        }
        HttpURLConnection upstream =
            (HttpURLConnection) target.toURL().openConnection(Proxy.NO_PROXY);
        upstream.setRequestMethod(exchange.getRequestMethod());
        int code = upstream.getResponseCode();
        byte[] body;
        try (InputStream in = code >= 400 ? upstream.getErrorStream() : upstream.getInputStream()) {
          body = in == null ? new byte[0] : in.readAllBytes();
        }
        String type = upstream.getContentType();
        if (type != null) {
          exchange.getResponseHeaders().set("Content-Type", type);
        }
        exchange.sendResponseHeaders(code, body.length == 0 ? -1 : body.length);
        try (OutputStream out = exchange.getResponseBody()) {
          out.write(body);
        }
      });
      server.start();
      return proxy;
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  /** {@code host:port}, as the proxy properties want it. */
  public String hostPort() {
    return "127.0.0.1:" + server.getAddress().getPort();
  }

  public int port() {
    return server.getAddress().getPort();
  }

  public List<String> forwarded() {
    return List.copyOf(forwarded);
  }

  @Override
  public void close() {
    server.stop(0);
  }
}
