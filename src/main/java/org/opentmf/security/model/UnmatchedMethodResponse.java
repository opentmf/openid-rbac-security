package org.opentmf.security.model;

/**
 * How to answer a denied request whose path is served by the application, but not for the
 * HTTP method that was used.
 *
 * <p>Used by both the main-port section ({@code opentmf.security.unmatched-method-response})
 * and the management-port section
 * ({@code opentmf.security.management.unmatched-method-response}). Both default to
 * {@link #METHOD_NOT_ALLOWED}.
 *
 * <p>This only ever changes the response written for a request that was <em>already</em>
 * denied. It never grants access, and the request never reaches a controller either way.
 *
 * @author Gokhan Demir
 */
public enum UnmatchedMethodResponse {

  /**
   * Answer {@code 405 Method Not Allowed} with an {@code Allow} header listing the methods
   * the application actually serves on that path, exactly as Spring itself would answer had
   * the access rules permitted the request through to the dispatcher.
   *
   * <p>A plain {@code OPTIONS} request is answered {@code 200 OK} with the same header
   * instead, since {@code OPTIONS} asks a question rather than attempting an operation.
   *
   * <p>The response carries no body. Note that a consumer-supplied
   * {@code AccessDeniedHandler} is not invoked for these responses; it still handles every
   * other denial.
   */
  METHOD_NOT_ALLOWED,

  /**
   * Answer every denial the same way, with {@code 403 Forbidden} and no {@code Allow}
   * header. Restores the behavior of releases before 3.0.0. Choose this to keep the set of
   * methods an application implements from being disclosed, or when a consumer relies on
   * {@code 403} for requests that use an unsupported method.
   */
  DENY
}
