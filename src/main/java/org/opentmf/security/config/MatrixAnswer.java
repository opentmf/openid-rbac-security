package org.opentmf.security.config;

import java.util.Set;
import org.springframework.http.HttpMethod;

/**
 * What the HTTP-status matrix decides for one request, before authentication and before the
 * access rules — see {@link EndpointRules#answerFor}.
 *
 * @param kind the row of the matrix the request landed on
 * @param allow the methods an {@link Kind#OPTIONS} answer advertises; empty for every other kind
 * @author Gokhan Demir
 */
public record MatrixAnswer(Kind kind, Set<HttpMethod> allow) {

  /** The rows of the matrix. */
  public enum Kind {
    /** No handler serves the path: {@code 404}, whoever asks. */
    NOT_FOUND,
    /** The path is served, the method is not implemented on it: {@code 405}, no {@code Allow}. */
    METHOD_NOT_ALLOWED,
    /** A plain {@code OPTIONS} on a served path: {@code 200} with the methods Spring would list. */
    OPTIONS,
    /** Path and method exist: the request goes on to authentication and the access rules. */
    PROCEED
  }

  private static final MatrixAnswer NOT_FOUND = new MatrixAnswer(Kind.NOT_FOUND, Set.of());
  private static final MatrixAnswer METHOD_NOT_ALLOWED =
      new MatrixAnswer(Kind.METHOD_NOT_ALLOWED, Set.of());
  private static final MatrixAnswer PROCEED = new MatrixAnswer(Kind.PROCEED, Set.of());

  public static MatrixAnswer notFound() {
    return NOT_FOUND;
  }

  public static MatrixAnswer methodNotAllowed() {
    return METHOD_NOT_ALLOWED;
  }

  public static MatrixAnswer proceed() {
    return PROCEED;
  }

  public static MatrixAnswer options(Set<HttpMethod> allow) {
    return new MatrixAnswer(Kind.OPTIONS, allow);
  }
}
