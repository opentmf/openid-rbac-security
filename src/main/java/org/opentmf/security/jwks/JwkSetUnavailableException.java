package org.opentmf.security.jwks;

import java.net.URI;
import java.time.Duration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

/**
 * The signing keys of an issuer have never been obtained and cannot be fetched now, so no
 * bearer token from that issuer can be verified — a {@code 503} with {@code Retry-After},
 * not an authentication failure: the caller's token may well be valid.
 *
 * <p>Deliberately not an {@code AuthenticationException}: those are routed to the security
 * entry point and become {@code 401}, which would tell a caller with a valid token that the
 * token is bad. As an {@code ErrorResponse} it is rendered by the library through the
 * application's own error rendering — and, when an adopter decodes tokens itself through
 * {@code JwtService}, by the adopter's exception mapping — with the issuer named by its
 * configured name, never by its URL.
 *
 * @author Gokhan Demir
 */
public class JwkSetUnavailableException extends ResponseStatusException {

  /** The problem type that identifies this outcome to a client. */
  public static final URI TYPE = URI.create("urn:opentmf:security:problem:signing-keys-unavailable");

  private final String issuerName;
  private final Duration retryAfter;

  public JwkSetUnavailableException(String issuerName, Duration retryAfter, Throwable cause) {
    super(HttpStatus.SERVICE_UNAVAILABLE,
        "Signing keys of issuer '" + issuerName + "' are not available", cause);
    this.issuerName = issuerName;
    this.retryAfter = retryAfter;
    setTitle("Signing keys unavailable");
    setType(TYPE);
    setDetail(getReason());
    getBody().setProperty("issuer", issuerName);
  }

  public String getIssuerName() {
    return issuerName;
  }

  public Duration getRetryAfter() {
    return retryAfter;
  }

  @Override
  public HttpHeaders getHeaders() {
    HttpHeaders headers = new HttpHeaders();
    headers.set(HttpHeaders.RETRY_AFTER, String.valueOf(retryAfter.toSeconds()));
    return headers;
  }
}
