package org.opentmf.security;

import static org.opentmf.security.util.TokenUtil.EXPIRED_TOKEN;
import static org.opentmf.security.util.TokenUtil.READ_TOKEN;
import static org.opentmf.security.util.TokenUtil.WRITE_TOKEN;

import java.util.List;
import java.util.stream.Stream;

/**
 * The HTTP-status matrix as a table, shared by every stack's and every port's contract test.
 *
 * <p>Evaluated in this order for every request: (1) no handler for the path → {@code 404},
 * whoever asks; (2) the path exists, the method is not implemented on it — unknown method names
 * included — → {@code 405} with no {@code Allow}; (3) no token or an invalid one → {@code 401};
 * (4) a valid token without the role → {@code 403}. A plain {@code OPTIONS} on a mapped path is
 * an existing method: {@code 401} without a token, Spring's {@code 200} + {@code Allow} with one.
 *
 * <p>The main-port table assumes the test application with {@code whitelist: /whitelist/**},
 * {@code blacklist: /protectedButNotConfigured} and {@code other-endpoints: deny}; the paths:
 *
 * <ul>
 *   <li>{@code /car} — mapped {@code GET} (allowed anonymously), {@code POST} and {@code PUT}
 *       (role {@code write});</li>
 *   <li>{@code /car/{name}} — mapped {@code GET} (roles {@code read}, {@code write}) and
 *       {@code DELETE} ({@code write}); {@code /car/a/b} is a path variable carrying a
 *       {@code /} and falls off the route table;</li>
 *   <li>{@code /whitelist} — mapped {@code GET}, whitelisted; {@code /whitelist/nothing} is an
 *       unmapped path under the whitelisted prefix;</li>
 *   <li>{@code /protectedButNotConfigured} — mapped {@code GET}, blacklisted;</li>
 *   <li>{@code /fn} — a functional route, {@code GET} only, with no rule of its own;</li>
 *   <li>{@code /probe.txt} — a static resource behind Boot's default {@code /**} resource
 *       handler, with no rule of its own; {@code /missing.txt} is not there;</li>
 *   <li>{@code /nothing/here} — unmapped.</li>
 * </ul>
 *
 * @author Gokhan Demir
 */
final class HttpStatusMatrixCells {

  /** Who is asking. */
  enum Caller {
    ANONYMOUS(null),
    INVALID_TOKEN(EXPIRED_TOKEN),
    READER(READ_TOKEN),
    WRITER(WRITE_TOKEN);

    final String token;

    Caller(String token) {
      this.token = token;
    }
  }

  /** How a cell must be answered, beyond the status. */
  enum Body {
    /** The application's error rendering: its marker, never Boot's default JSON, no Allow. */
    APPLICATION_ERROR,
    /** Spring Security's RFC 6750 default: {@code WWW-Authenticate}, empty body. */
    CHALLENGE,
    /** Whatever the application answered; only the status is asserted. */
    ANY,
    /** A plain {@code OPTIONS} answer: {@code Allow} present, empty body. */
    ALLOW
  }

  record Cell(String method, String path, Caller caller, int status, Body body) {

    @Override
    public String toString() {
      return method + " " + path + " as " + caller + " -> " + status;
    }
  }

  private static Cell cell(String method, String path, Caller caller, int status, Body body) {
    return new Cell(method, path, caller, status, body);
  }

  /** Every caller gets the same answer: the cell does not depend on who asks. */
  private static Stream<Cell> forEveryCaller(String method, String path, int status, Body body) {
    return Stream.of(Caller.values()).map(caller -> cell(method, path, caller, status, body));
  }

  private HttpStatusMatrixCells() {
    // Table.
  }

  /** The main-port matrix. */
  static Stream<Cell> mainPort() {
    return Stream.of(
        // ---- row 1: no handler for the path -> 404, anonymous or authenticated
        forEveryCaller("GET", "/nothing/here", 404, Body.APPLICATION_ERROR),
        forEveryCaller("POST", "/nothing/here", 404, Body.APPLICATION_ERROR),
        forEveryCaller("PROPFIND", "/nothing/here", 404, Body.APPLICATION_ERROR),
        forEveryCaller("OPTIONS", "/nothing/here", 404, Body.APPLICATION_ERROR),
        forEveryCaller("GET", "/car/a/b", 404, Body.APPLICATION_ERROR),
        forEveryCaller("GET", "/whitelist/nothing", 404, Body.APPLICATION_ERROR),
        forEveryCaller("BREW", "/whitelist/nothing", 404, Body.APPLICATION_ERROR),
        forEveryCaller("GET", "/missing.txt", 404, Body.APPLICATION_ERROR),
        // a functional route matches its method or nothing at all, so this is a 404 natively too
        forEveryCaller("PATCH", "/fn", 404, Body.APPLICATION_ERROR),
        // ---- row 2: the path exists, the method is not implemented -> 405, no Allow
        forEveryCaller("PATCH", "/car", 405, Body.APPLICATION_ERROR),
        forEveryCaller("PROPFIND", "/car", 405, Body.APPLICATION_ERROR),
        forEveryCaller("BREW", "/car", 405, Body.APPLICATION_ERROR),
        forEveryCaller("PUT", "/car/Mercedes", 405, Body.APPLICATION_ERROR),
        forEveryCaller("PATCH", "/car/Mercedes", 405, Body.APPLICATION_ERROR),
        forEveryCaller("POST", "/whitelist", 405, Body.APPLICATION_ERROR),
        forEveryCaller("PROPFIND", "/whitelist", 405, Body.APPLICATION_ERROR),
        forEveryCaller("PATCH", "/protectedButNotConfigured", 405, Body.APPLICATION_ERROR),
        forEveryCaller("POST", "/probe.txt", 405, Body.APPLICATION_ERROR),
        forEveryCaller("PROPFIND", "/probe.txt", 405, Body.APPLICATION_ERROR),
        // ---- rows 3 and 4: path and method exist -> 401 without a valid token, 403 sans role
        Stream.of(
            cell("POST", "/car", Caller.ANONYMOUS, 401, Body.CHALLENGE),
            cell("POST", "/car", Caller.INVALID_TOKEN, 401, Body.CHALLENGE),
            cell("POST", "/car", Caller.READER, 403, Body.ANY),
            cell("DELETE", "/car/Mercedes", Caller.ANONYMOUS, 401, Body.CHALLENGE),
            cell("DELETE", "/car/Mercedes", Caller.READER, 403, Body.ANY),
            cell("GET", "/car/Mercedes", Caller.ANONYMOUS, 401, Body.CHALLENGE),
            cell("GET", "/car/Mercedes", Caller.INVALID_TOKEN, 401, Body.CHALLENGE),
            cell("HEAD", "/car/Mercedes", Caller.ANONYMOUS, 401, Body.CHALLENGE),
            cell("GET", "/fn", Caller.ANONYMOUS, 401, Body.CHALLENGE),
            cell("GET", "/fn", Caller.INVALID_TOKEN, 401, Body.CHALLENGE),
            cell("GET", "/fn", Caller.READER, 403, Body.ANY),
            cell("GET", "/probe.txt", Caller.ANONYMOUS, 401, Body.CHALLENGE),
            cell("GET", "/probe.txt", Caller.READER, 403, Body.ANY),
            cell("GET", "/protectedButNotConfigured", Caller.ANONYMOUS, 401, Body.CHALLENGE),
            cell("GET", "/protectedButNotConfigured", Caller.WRITER, 403, Body.ANY),
            // ---- and what is served stays served
            cell("GET", "/car", Caller.ANONYMOUS, 200, Body.ANY),
            cell("HEAD", "/car", Caller.ANONYMOUS, 200, Body.ANY),
            cell("GET", "/car", Caller.WRITER, 200, Body.ANY),
            cell("GET", "/whitelist", Caller.ANONYMOUS, 200, Body.ANY),
            cell("GET", "/whitelist", Caller.INVALID_TOKEN, 401, Body.CHALLENGE),
            cell("GET", "/fn", Caller.WRITER, 403, Body.ANY),
            // ---- plain OPTIONS: an existing method — 401 without a token, Spring's with one
            cell("OPTIONS", "/car", Caller.ANONYMOUS, 401, Body.CHALLENGE),
            cell("OPTIONS", "/car", Caller.INVALID_TOKEN, 401, Body.CHALLENGE),
            cell("OPTIONS", "/car", Caller.READER, 200, Body.ALLOW),
            cell("OPTIONS", "/car", Caller.WRITER, 200, Body.ALLOW),
            cell("OPTIONS", "/car/Mercedes", Caller.READER, 200, Body.ALLOW),
            cell("OPTIONS", "/whitelist", Caller.ANONYMOUS, 200, Body.ALLOW),
            cell("OPTIONS", "/protectedButNotConfigured", Caller.ANONYMOUS, 401, Body.CHALLENGE),
            cell("OPTIONS", "/protectedButNotConfigured", Caller.WRITER, 200, Body.ALLOW)))
        .flatMap(cells -> cells);
  }

  /** What {@code OPTIONS} on {@code /car} must advertise: Spring's own set for the mapping. */
  static final List<String> OPTIONS_ALLOW_ON_CAR =
      List.of("GET", "HEAD", "POST", "PUT", "OPTIONS");

  /**
   * The management-port matrix, for a port with {@code other-endpoints: deny}, the default
   * whitelist, and {@code GET /actuator/metrics} secured for role {@code write}.
   */
  static Stream<Cell> managementPort() {
    return Stream.of(
        forEveryCaller("GET", "/actuator/nothing", 404, Body.APPLICATION_ERROR),
        forEveryCaller("PATCH", "/car", 404, Body.APPLICATION_ERROR),
        forEveryCaller("PUT", "/actuator/metrics", 405, Body.APPLICATION_ERROR),
        forEveryCaller("PROPFIND", "/actuator/metrics", 405, Body.APPLICATION_ERROR),
        forEveryCaller("POST", "/actuator/health", 405, Body.APPLICATION_ERROR),
        Stream.of(
            cell("GET", "/actuator/metrics", Caller.ANONYMOUS, 401, Body.CHALLENGE),
            cell("GET", "/actuator/metrics", Caller.INVALID_TOKEN, 401, Body.CHALLENGE),
            cell("GET", "/actuator/metrics", Caller.READER, 403, Body.ANY),
            cell("GET", "/actuator/metrics", Caller.WRITER, 200, Body.ANY),
            cell("GET", "/actuator/health", Caller.ANONYMOUS, 200, Body.ANY),
            cell("OPTIONS", "/actuator/metrics", Caller.ANONYMOUS, 401, Body.CHALLENGE),
            cell("OPTIONS", "/actuator/metrics", Caller.WRITER, 200, Body.ALLOW)))
        .flatMap(cells -> cells);
  }
}
