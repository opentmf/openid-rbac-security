package org.opentmf.security.jwks;

import java.util.List;
import java.util.function.UnaryOperator;
import org.opentmf.security.config.CommonConfig;
import org.opentmf.security.config.ResolvedIssuer;
import org.opentmf.security.model.OpenTmfSecurityProperties;

/**
 * The signing keys of every trusted issuer, in configuration order — built once per
 * application and shared by both stacks' decoders and by the warm-up, so that each issuer has
 * exactly one cache, one background refresh and one first load however many chains use it.
 *
 * @author Gokhan Demir
 */
public class TrustedIssuerKeys {

  private final List<IssuerKeys> issuers;

  public TrustedIssuerKeys(OpenTmfSecurityProperties properties) {
    this(properties, System::getenv);
  }

  /**
   * @param environment reads a process environment variable, {@code null} when absent — the
   *     production value is {@code System::getenv}
   */
  public TrustedIssuerKeys(OpenTmfSecurityProperties properties, UnaryOperator<String> environment) {
    this.issuers = CommonConfig.resolveIssuers(properties).stream()
        .map(issuer -> new IssuerKeys(
            issuer.name(), issuer.jwkSetUri(), issuer.proxy(), properties.getJwks(), environment))
        .toList();
  }

  /** One entry per resolved issuer, in the order {@link CommonConfig#resolveIssuers} yields. */
  public List<IssuerKeys> issuers() {
    return issuers;
  }

  /** The keys of the resolved issuer at the given position. */
  public IssuerKeys forIssuer(int index, ResolvedIssuer issuer) {
    IssuerKeys keys = issuers.get(index);
    if (!keys.name().equals(issuer.name())) {
      throw new IllegalStateException(
          "Issuer keys are out of step with the resolved issuers: " + keys.name() + " vs "
              + issuer.name());
    }
    return keys;
  }
}
