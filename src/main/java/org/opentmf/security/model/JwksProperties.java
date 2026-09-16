package org.opentmf.security.model;

import jakarta.validation.constraints.NotNull;
import java.time.Duration;
import lombok.Getter;
import lombok.Setter;

/**
 * How the signing keys of every trusted issuer are fetched and cached — the
 * {@code opentmf.security.jwks} section. Every default reproduces the fetch a service performed
 * before 3.2.0 wherever that fetch succeeded, so a deployment whose issuers are reachable needs
 * none of these; they matter when an issuer is slow, unreachable, or behind a proxy.
 *
 * @author Gokhan Demir
 */
@Getter
@Setter
public class JwksProperties {

  /**
   * How long a fetched JWK set is served before a refresh is attempted. The refresh runs in the
   * background, ahead of expiry, never on a request thread.
   */
  private @NotNull Duration cacheTtl = Duration.ofMinutes(5);

  /**
   * How long the last successfully fetched JWK set keeps being served while refreshes fail —
   * the bounded staleness during an identity-provider outage. Only a deployment that has never
   * obtained the keys at all answers {@code 503}.
   */
  private @NotNull Duration outageTtl = Duration.ofHours(24);

  /**
   * The minimum interval between two forced refreshes, which a token with an unknown key id
   * triggers — so key rotation is picked up within one interval and a flood of unknown key ids
   * cannot turn into a flood of fetches. Also the {@code Retry-After} a {@code 503} advertises.
   */
  private @NotNull Duration refreshInterval = Duration.ofSeconds(30);

  /**
   * Connect timeout of the fetch. Unset, the JVM property the pre-3.2.0 fetch honoured applies
   * ({@code sun.net.client.defaultConnectTimeout}), then 30 seconds.
   */
  private Duration connectTimeout;

  /**
   * Read timeout of the fetch. Unset, the JVM property the pre-3.2.0 fetch honoured applies
   * ({@code sun.net.client.defaultReadTimeout}), then 30 seconds.
   */
  private Duration readTimeout;

  /**
   * The proxy the fetch goes through, as {@code host:port}, for single-issuer mode. Overrides
   * the JVM's proxy properties and the {@code HTTPS_PROXY} / {@code NO_PROXY} environment,
   * which are honoured in that order when this is unset. In multi-issuer mode set
   * {@code opentmf.security.issuers[].proxy} per issuer instead.
   */
  private String proxy;

  /** What to do when the keys cannot be obtained at startup; see {@link JwksStartupFailure}. */
  private @NotNull JwksStartupFailure onStartupFailure = JwksStartupFailure.WARN;
}
