package org.opentmf.security.model;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

/**
 * The declaration of trust is the one thing a deployer cannot get silently wrong: a service that
 * trusts nothing, trusts two contradictory things, or routes ambiguously must fail to boot
 * rather than start and behave unexpectedly. These pin those rules.
 *
 * @author Gokhan Demir
 */
@TestInstance(Lifecycle.PER_CLASS)
class OpenTmfSecurityPropertiesValidationTest {

  private static final Resource JWK_SET = new ClassPathResource("jwk-set.json");

  private ValidatorFactory factory;
  private Validator validator;

  @BeforeAll
  void setUp() {
    factory = Validation.buildDefaultValidatorFactory();
    validator = factory.getValidator();
  }

  @AfterAll
  void tearDown() {
    factory.close();
  }

  @Test
  void singleIssuerConfiguration_isValid() {
    OpenTmfSecurityProperties properties = new OpenTmfSecurityProperties();
    properties.setJwkSetUri(JWK_SET);

    assertThat(validator.validate(properties)).isEmpty();
  }

  @Test
  void multiIssuerConfiguration_isValid() {
    OpenTmfSecurityProperties properties = new OpenTmfSecurityProperties();
    properties.setIssuers(List.of(
        issuer("entra", "https://login.microsoftonline.com/tenant/v2.0"),
        issuer("keycloak", "https://keycloak.test/realms/dnms")));

    assertThat(validator.validate(properties)).isEmpty();
  }

  @Test
  void noTrustDeclaredAtAll_isRejected() {
    OpenTmfSecurityProperties properties = new OpenTmfSecurityProperties();

    assertThat(messages(properties)).anyMatch(message -> message.contains("exactly one"));
  }

  @Test
  void bothTrustStylesDeclared_isRejected() {
    OpenTmfSecurityProperties properties = new OpenTmfSecurityProperties();
    properties.setJwkSetUri(JWK_SET);
    properties.setIssuers(List.of(issuer("entra", "https://login.microsoftonline.com/t/v2.0")));

    assertThat(messages(properties)).anyMatch(message -> message.contains("exactly one"));
  }

  @Test
  void duplicateIssuerValue_isRejected() {
    OpenTmfSecurityProperties properties = new OpenTmfSecurityProperties();
    properties.setIssuers(List.of(
        issuer("first", "https://same.test/realms/dnms"),
        issuer("second", "https://same.test/realms/dnms")));

    assertThat(messages(properties)).anyMatch(message -> message.contains("issuer must be unique"));
  }

  @Test
  void duplicateIssuerName_isRejected() {
    OpenTmfSecurityProperties properties = new OpenTmfSecurityProperties();
    properties.setIssuers(List.of(
        issuer("same-name", "https://one.test/realms/dnms"),
        issuer("same-name", "https://two.test/realms/dnms")));

    assertThat(messages(properties)).anyMatch(message -> message.contains("name must be unique"));
  }

  @Test
  void blankIssuerNames_doNotCountAsDuplicates() {
    OpenTmfSecurityProperties properties = new OpenTmfSecurityProperties();
    properties.setIssuers(List.of(
        issuer(null, "https://one.test/realms/dnms"),
        issuer(null, "https://two.test/realms/dnms")));

    assertThat(validator.validate(properties)).isEmpty();
  }

  @Test
  void issuerEntryWithoutIssuerOrKeys_isRejected() {
    OpenTmfSecurityProperties properties = new OpenTmfSecurityProperties();
    IssuerProperties incomplete = new IssuerProperties();
    incomplete.setName("incomplete");
    properties.setIssuers(List.of(incomplete));

    assertThat(validator.validate(properties)).hasSizeGreaterThanOrEqualTo(2);
  }

  private Set<String> messages(OpenTmfSecurityProperties properties) {
    return validator.validate(properties).stream()
        .map(ConstraintViolation::getMessage)
        .collect(Collectors.toSet());
  }

  private static IssuerProperties issuer(String name, String issuer) {
    IssuerProperties properties = new IssuerProperties();
    properties.setName(name);
    properties.setIssuer(issuer);
    properties.setJwkSetUri(JWK_SET);
    return properties;
  }
}
