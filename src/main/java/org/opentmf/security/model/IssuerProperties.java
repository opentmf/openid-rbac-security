package org.opentmf.security.model;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import java.util.ArrayList;
import java.util.List;
import lombok.Getter;
import lombok.Setter;
import org.springframework.core.io.Resource;

/**
 * One trusted token issuer. Configured under {@code opentmf.security.issuers[]} when a service
 * must accept tokens from more than one identity provider — for example Entra ID for
 * user-driven calls and Keycloak for service-to-service calls on the same resource server.
 *
 * <p>Endpoint rules ({@code secure-endpoints}, {@code whitelist}, …) never fork per issuer:
 * each entry's claim mapping normalizes its provider's token shape onto the same internal
 * role vocabulary, so authorization stays provider-blind.
 *
 * @author Gokhan Demir
 */
@Getter
@Setter
public class IssuerProperties {

  /**
   * Optional human-readable label for this issuer, used in log messages (for example
   * {@code entra} or {@code keycloak}). Must be unique across entries when set. Has no effect
   * on token validation.
   */
  private String name;

  /**
   * The exact {@code iss} claim value tokens from this provider carry. Incoming tokens are
   * routed to this entry by matching it, and the entry's decoder additionally validates it.
   *
   * <p><strong>Entra trap:</strong> the v2 issuer is tenant-specific
   * ({@code https://login.microsoftonline.com/{tenantId}/v2.0}), while an app registration
   * left on token version 1 emits {@code https://sts.windows.net/{tenantId}/} instead. Decode
   * a real token and copy the {@code iss} verbatim rather than assuming.
   */
  private @NotBlank String issuer;

  /**
   * Where this issuer's signing keys are fetched from. Same resource semantics as the
   * single-issuer {@link OpenTmfSecurityProperties#getJwkSetUri()} — an HTTPS URL in
   * production, or a {@code classpath:} / {@code file:} pointer in tests.
   */
  private @NotNull Resource jwkSetUri;

  /**
   * The claim to use as the principal for tokens from this issuer. Falls back to the
   * top-level {@code opentmf.security.user-claim} when omitted, then to {@code sub}.
   *
   * <p>For Entra prefer {@code oid} (stable object id) with {@code preferred_username} as a
   * readable fallback.
   */
  private String userClaim;

  /**
   * Claims tried in order when {@link #getUserClaim()} is absent from a token. Falls back to
   * the top-level {@code opentmf.security.fallback-user-claims} when omitted; set an empty
   * list to explicitly opt out of the inherited value.
   */
  private List<String> fallbackUserClaims;

  /**
   * The claim carrying this issuer's roles. Falls back to the top-level
   * {@code opentmf.security.authorities-claim} when omitted, then to {@code roles}.
   *
   * <p>For Entra prefer App Roles ({@code roles}) over {@code groups}: group claims truncate
   * into a pointer claim past roughly 200 memberships, while app roles always arrive inline
   * and can be named after the internal vocabulary so mapping is an identity.
   */
  private String authoritiesClaim;

  /**
   * Accepted values of the {@code aud} claim. When empty (the default) the audience is not
   * validated; when set, a token is rejected unless its {@code aud} contains at least one of
   * these values.
   *
   * <p>Strongly recommended in production for providers that mint tokens for many
   * applications from one tenant: without it, a token issued to a completely different
   * application of the same tenant still satisfies the issuer check. Verify against a real
   * token before enabling — a wrong value rejects every request from that issuer.
   */
  private List<@NotEmpty String> audiences = new ArrayList<>();
}
