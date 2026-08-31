package org.opentmf.security.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.opentmf.security.config.management.ReactiveManagementSecurityAutoConfiguration;
import org.opentmf.security.config.management.ServletManagementSecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.ReactiveWebApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.boot.webflux.autoconfigure.WebFluxAutoConfiguration;
import org.springframework.boot.webmvc.autoconfigure.WebMvcAutoConfiguration;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.server.SecurityWebFilterChain;

/**
 * This library ships an auto-configuration layer for each stack and a consumer only ever has one
 * of them. Neither layer may fail — or even be loaded — because of the other's absence.
 *
 * <p>The risk is not theoretical: both layers name types from their own stack that a consumer of
 * the other stack does not have on the classpath at all, since {@code spring-boot-starter-webmvc}
 * and {@code spring-boot-starter-webflux} are both {@code optional} dependencies here. What keeps
 * that safe is that Spring Boot evaluates {@code @ConditionalOnWebApplication} from ASM-read
 * metadata, so a class whose condition does not match is never loaded and its references are
 * never resolved. These tests hold that guarantee to the fire by hiding each stack outright.
 *
 * @author Gokhan Demir
 */
class StackIsolationTest {

  private static final String JWK_SET = "opentmf.security.jwk-set-uri=classpath:jwk-set.json";

  /** A WebFlux-free classpath, as any plain Spring MVC consumer has. */
  @Test
  void servletStack_startsWithWebFluxAbsent() {
    new WebApplicationContextRunner()
        .withClassLoader(new FilteredClassLoader("org.springframework.web.reactive"))
        .withConfiguration(AutoConfigurations.of(
            WebMvcAutoConfiguration.class,
            ServletJwtAutoConfiguration.class,
            ServletSecurityAutoConfiguration.class,
            ReactiveJwtAutoConfiguration.class,
            ReactiveSecurityAutoConfiguration.class,
            ServletManagementSecurityAutoConfiguration.class))
        .withPropertyValues(JWK_SET)
        .run(context -> {
          assertThat(context).hasNotFailed();
          assertThat(context).hasSingleBean(SecurityFilterChain.class);
          assertThat(context).doesNotHaveBean(SecurityWebFilterChain.class);
        });
  }

  /** A Spring-MVC-free classpath, as any plain WebFlux consumer has. */
  @Test
  void reactiveStack_startsWithSpringMvcAbsent() {
    new ReactiveWebApplicationContextRunner()
        .withClassLoader(new FilteredClassLoader("org.springframework.web.servlet"))
        .withConfiguration(AutoConfigurations.of(
            WebFluxAutoConfiguration.class,
            ReactiveJwtAutoConfiguration.class,
            ReactiveSecurityAutoConfiguration.class,
            ServletJwtAutoConfiguration.class,
            ServletSecurityAutoConfiguration.class,
            ServletManagementSecurityAutoConfiguration.class))
        .withPropertyValues(JWK_SET)
        .run(context -> {
          assertThat(context).hasNotFailed();
          assertThat(context).hasSingleBean(SecurityWebFilterChain.class);
          assertThat(context).doesNotHaveBean(SecurityFilterChain.class);
        });
  }

  /**
   * The stricter of the two: a WebFlux consumer typically has no servlet API either, so the
   * servlet layer must survive {@code jakarta.servlet} itself being absent.
   */
  @Test
  void reactiveStack_startsWithTheServletApiAbsentToo() {
    new ReactiveWebApplicationContextRunner()
        .withClassLoader(new FilteredClassLoader(
            "org.springframework.web.servlet", "jakarta.servlet"))
        .withConfiguration(AutoConfigurations.of(
            WebFluxAutoConfiguration.class,
            ReactiveJwtAutoConfiguration.class,
            ReactiveSecurityAutoConfiguration.class,
            ServletJwtAutoConfiguration.class,
            ServletSecurityAutoConfiguration.class,
            ServletManagementSecurityAutoConfiguration.class))
        .withPropertyValues(JWK_SET)
        .run(context -> {
          assertThat(context).hasNotFailed();
          assertThat(context).hasSingleBean(SecurityWebFilterChain.class);
        });
  }

  // ------------------------------------------------------------------ bytecode

  /**
   * The context-runner tests above hand Spring already-loaded {@code Class} objects, so they
   * prove the conditions skip the wrong stack's beans — not that the wrong stack's class could
   * have been loaded at all. In production Boot loads auto-configurations by name and skips a
   * non-matching one without loading it, which is what makes the absent stack harmless.
   *
   * <p>These two check the property that guarantee rests on, straight from the compiled class:
   * a servlet auto-configuration must not name a WebFlux type anywhere in its constant pool, and
   * a reactive one must not name a Spring MVC or servlet-API type. Any such reference would be
   * resolved the moment the class were loaded for a consumer that does not have that stack.
   */
  @ParameterizedTest
  @ValueSource(classes = {
      ServletSecurityAutoConfiguration.class,
      ServletJwtAutoConfiguration.class,
      ServletManagementSecurityAutoConfiguration.class,
      ServletSupportedMethodsResolver.class,
      MethodNotAllowedAccessDeniedHandler.class})
  void servletClasses_nameNoWebFluxType(Class<?> type) throws IOException {
    assertThat(constantPoolOf(type))
        .doesNotContain("org/springframework/web/reactive")
        .doesNotContain("reactor/core/publisher");
  }

  @ParameterizedTest
  @ValueSource(classes = {
      ReactiveSecurityAutoConfiguration.class,
      ReactiveJwtAutoConfiguration.class,
      ReactiveManagementSecurityAutoConfiguration.class,
      ReactiveSupportedMethodsResolver.class,
      MethodNotAllowedServerAccessDeniedHandler.class})
  void reactiveClasses_nameNoSpringMvcOrServletType(Class<?> type) throws IOException {
    assertThat(constantPoolOf(type))
        .doesNotContain("org/springframework/web/servlet")
        .doesNotContain("jakarta/servlet");
  }

  /** The raw bytes of a compiled class, in which every referenced type appears verbatim. */
  private static String constantPoolOf(Class<?> type) throws IOException {
    String resource = type.getName().replace('.', '/') + ".class";
    try (InputStream in = type.getClassLoader().getResourceAsStream(resource)) {
      assertThat(in).as("compiled class for %s", type.getName()).isNotNull();
      return new String(in.readAllBytes(), StandardCharsets.ISO_8859_1);
    }
  }
}
