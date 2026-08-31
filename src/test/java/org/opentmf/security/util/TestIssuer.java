package org.opentmf.security.util;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.function.Consumer;
import lombok.Getter;

/**
 * A self-contained token issuer for the multi-issuer tests: generates its own RSA key pair,
 * publishes the public half as a JWK set on disk, and mints signed tokens carrying whatever
 * claim shape a test needs.
 *
 * <p>The committed {@code jwk-set.json} cannot be used for this — it holds only a public key,
 * so nothing can be signed with it, and the pre-issued constants in {@link TokenUtil} carry one
 * fixed {@code iss}. Those fixtures still drive the single-issuer tests; multi-issuer tests need
 * tokens that differ by issuer, audience and expiry, which means minting them here.
 *
 * @author Gokhan Demir
 */
public final class TestIssuer {

  private static final Path JWK_SET_DIR = Path.of("target", "test-issuers");

  /**
   * The one clock the minted claims read. These tokens are validated by real decoders against
   * wall-clock time, so — unlike a fixture nothing re-validates — this clock genuinely cannot
   * be fixed: a frozen instant would make every minted token invalid or eternally fresh in the
   * eyes of the decoder under test. It is named once here rather than reached for via bare
   * {@code Instant.now()} at every call site.
   */
  @SuppressWarnings("java:S8692")
  private static final Clock CLOCK = Clock.systemUTC();

  /** The current instant on the issuer's clock — also for tests minting relative expiries. */
  public static Instant now() {
    return Instant.now(CLOCK);
  }

  /** The {@code iss} value tokens from this issuer carry. */
  @Getter
  private final String issuer;

  /** Points at the on-disk JWK set, for {@code opentmf.security.issuers[n].jwk-set-uri}. */
  @Getter
  private final String jwkSetUri;

  private final RSAKey signingKey;

  private TestIssuer(String issuer, String jwkSetUri, RSAKey signingKey) {
    this.issuer = issuer;
    this.jwkSetUri = jwkSetUri;
    this.signingKey = signingKey;
  }

  /**
   * Creates an issuer whose JWK set lands in {@code target/} under the given name, so
   * {@code mvn clean} disposes of it.
   */
  public static TestIssuer create(String name, String issuer) {
    try {
      RSAKey key = new RSAKeyGenerator(2048)
          .keyID(name + "-key")
          .algorithm(JWSAlgorithm.RS256)
          .generate();
      Files.createDirectories(JWK_SET_DIR);
      Path jwkSetFile = JWK_SET_DIR.resolve(name + "-jwk-set.json");
      Files.writeString(jwkSetFile, new JWKSet(key.toPublicJWK()).toString());
      return new TestIssuer(issuer, jwkSetFile.toUri().toString(), key);
    } catch (JOSEException e) {
      throw new IllegalStateException("Could not generate a signing key for issuer " + name, e);
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  /**
   * Mints a token that is valid for an hour, carrying this issuer's {@code iss} and a
   * {@code sub}. The customizer adds the claims under test — roles, audience, a different
   * expiry, and so on.
   */
  public String mint(Consumer<JWTClaimsSet.Builder> customizer) {
    JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
        .issuer(issuer)
        .subject("subject-of-" + issuer)
        .issueTime(Date.from(now()))
        .expirationTime(Date.from(now().plusSeconds(3600)));
    customizer.accept(claims);
    return sign(claims.build());
  }

  /**
   * Mints a token whose {@code iss} is not this issuer — for the "unknown issuer" cases. The
   * signature is still valid, proving the rejection comes from issuer routing rather than from
   * a broken signature.
   */
  public String mintWithIssuer(String otherIssuer, Consumer<JWTClaimsSet.Builder> customizer) {
    JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
        .subject("subject-of-" + otherIssuer)
        .issueTime(Date.from(now()))
        .expirationTime(Date.from(now().plusSeconds(3600)));
    if (otherIssuer != null) {
      claims.issuer(otherIssuer);
    }
    customizer.accept(claims);
    return sign(claims.build());
  }

  private String sign(JWTClaimsSet claims) {
    try {
      SignedJWT jwt = new SignedJWT(
          new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(signingKey.getKeyID()).build(),
          claims);
      jwt.sign(new RSASSASigner(signingKey));
      return jwt.serialize();
    } catch (JOSEException e) {
      throw new IllegalStateException("Could not sign a test token for issuer " + issuer, e);
    }
  }
}
