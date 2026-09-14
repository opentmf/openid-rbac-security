package org.opentmf.security.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.EnumSource.Mode;
import org.opentmf.security.model.Endpoint;
import org.opentmf.security.model.EndpointMethod;
import org.springframework.http.HttpMethod;

/**
 * @author Gokhan Demir
 */
class EndpointRulesTest {

  @Test
  void httpMethodsFor_whenGet_alsoCoversHead() {
    assertThat(EndpointRules.httpMethodsFor(endpoint(EndpointMethod.GET)))
        .containsExactly(HttpMethod.GET, HttpMethod.HEAD);
  }

  @ParameterizedTest
  @EnumSource(value = EndpointMethod.class, names = "GET", mode = Mode.EXCLUDE)
  void httpMethodsFor_whenNotGet_coversOnlyThatMethod(EndpointMethod method) {
    assertThat(EndpointRules.httpMethodsFor(endpoint(method)))
        .containsExactly(method.toHttpMethod());
  }

  @Test
  void optionsAllow_whenNothingDeclared_offersEveryMethodButTrace() {
    Set<HttpMethod> allowed = EndpointRules.optionsAllow(Set.of());

    assertThat(allowed)
        .contains(HttpMethod.GET, HttpMethod.HEAD, HttpMethod.OPTIONS)
        .doesNotContain(HttpMethod.TRACE);
  }

  @Test
  void optionsAllow_whenGetDeclared_slotsHeadInRightAfterGet() {
    // Spring's HttpOptionsHandler puts HEAD immediately after GET; matching its answer
    // byte for byte means matching the order too, so DELETE comes after HEAD here.
    assertThat(EndpointRules.optionsAllow(ordered(HttpMethod.GET, HttpMethod.DELETE)))
        .containsExactly(HttpMethod.GET, HttpMethod.HEAD, HttpMethod.DELETE, HttpMethod.OPTIONS);
  }

  @Test
  void optionsAllow_whenGetNotDeclared_doesNotAddHead() {
    assertThat(EndpointRules.optionsAllow(ordered(HttpMethod.POST)))
        .containsExactly(HttpMethod.POST, HttpMethod.OPTIONS);
  }

  @Test
  void optionsAllowHeader_joinsWithABareComma_asSpringsOptionsHandlerDoes() {
    assertThat(EndpointRules.optionsAllowHeader(ordered(HttpMethod.GET, HttpMethod.HEAD)))
        .isEqualTo("GET,HEAD");
  }

  // ------------------------------------------------------------------ the matrix

  @Test
  void answerFor_aPathNoHandlerServes_isNotFound_whateverTheMethod() {
    assertThat(EndpointRules.answerFor(HttpMethod.GET, SupportedMethods.notServed()).kind())
        .isEqualTo(MatrixAnswer.Kind.NOT_FOUND);
    assertThat(EndpointRules.answerFor(HttpMethod.OPTIONS, SupportedMethods.notServed()).kind())
        .isEqualTo(MatrixAnswer.Kind.NOT_FOUND);
    assertThat(EndpointRules.answerFor(HttpMethod.valueOf("BREW"), SupportedMethods.notServed())
        .kind()).isEqualTo(MatrixAnswer.Kind.NOT_FOUND);
  }

  @Test
  void answerFor_aMethodThePathDoesNotImplement_isMethodNotAllowed_unknownNamesIncluded() {
    var served = new SupportedMethods(ordered(HttpMethod.GET, HttpMethod.DELETE), false);

    assertThat(EndpointRules.answerFor(HttpMethod.PUT, served).kind())
        .isEqualTo(MatrixAnswer.Kind.METHOD_NOT_ALLOWED);
    assertThat(EndpointRules.answerFor(HttpMethod.valueOf("PROPFIND"), served).kind())
        .isEqualTo(MatrixAnswer.Kind.METHOD_NOT_ALLOWED);
    assertThat(EndpointRules.answerFor(HttpMethod.PUT, served).allow()).isEmpty();
  }

  @Test
  void answerFor_anImplementedMethod_proceeds() {
    var served = new SupportedMethods(ordered(HttpMethod.GET, HttpMethod.DELETE), false);

    assertThat(EndpointRules.answerFor(HttpMethod.DELETE, served).kind())
        .isEqualTo(MatrixAnswer.Kind.PROCEED);
  }

  /** Spring serves {@code HEAD} from the {@code GET} handler, so the matrix must too. */
  @Test
  void answerFor_headOnAGetPath_proceeds() {
    var served = new SupportedMethods(ordered(HttpMethod.GET), false);

    assertThat(EndpointRules.answerFor(HttpMethod.HEAD, served).kind())
        .isEqualTo(MatrixAnswer.Kind.PROCEED);
  }

  @Test
  void answerFor_aMappingThatNamesNoMethod_proceedsForEveryMethod() {
    var served = new SupportedMethods(Set.of(), true);

    assertThat(EndpointRules.answerFor(HttpMethod.valueOf("BREW"), served).kind())
        .isEqualTo(MatrixAnswer.Kind.PROCEED);
  }

  @Test
  void answerFor_plainOptions_isSpringsOptionsAnswer() {
    var served = new SupportedMethods(ordered(HttpMethod.GET, HttpMethod.POST), false);

    MatrixAnswer answer = EndpointRules.answerFor(HttpMethod.OPTIONS, served);

    assertThat(answer.kind()).isEqualTo(MatrixAnswer.Kind.OPTIONS);
    assertThat(answer.allow())
        .containsExactly(HttpMethod.GET, HttpMethod.HEAD, HttpMethod.POST, HttpMethod.OPTIONS);
  }

  @Test
  void answerFor_optionsTheApplicationMapsItself_proceeds() {
    var served = new SupportedMethods(ordered(HttpMethod.GET, HttpMethod.OPTIONS), false);

    assertThat(EndpointRules.answerFor(HttpMethod.OPTIONS, served).kind())
        .isEqualTo(MatrixAnswer.Kind.PROCEED);
  }

  private static Endpoint endpoint(EndpointMethod method) {
    Endpoint endpoint = new Endpoint();
    endpoint.setMethod(method);
    endpoint.setPath("/car");
    return endpoint;
  }

  private static Set<HttpMethod> ordered(HttpMethod... methods) {
    return new LinkedHashSet<>(Arrays.asList(methods));
  }
}
