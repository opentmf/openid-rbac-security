package org.opentmf.security.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.context.properties.bind.BindException;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;
import org.springframework.http.HttpMethod;

/**
 * The access-rule method is deliberately narrower than Spring's {@code HttpMethod}. A deployment
 * that names a verb outside the five must fail to start rather than bind to something that
 * quietly never applies — which is exactly what a separate {@code HEAD} rule used to do, since
 * the {@code GET} rule registered ahead of it always matched first.
 *
 * @author Gokhan Demir
 */
class EndpointMethodBindingTest {

  @ParameterizedTest
  @EnumSource(EndpointMethod.class)
  void everySupportedMethod_binds(EndpointMethod method) {
    Endpoint endpoint = bind(method.name());

    assertThat(endpoint.getMethod()).isEqualTo(method);
  }

  @ParameterizedTest
  @ValueSource(strings = {"HEAD", "OPTIONS", "TRACE", "CONNECT"})
  void aMethodOutsideTheFive_failsToBind(String method) {
    assertThatThrownBy(() -> bind(method))
        .isInstanceOf(BindException.class)
        .hasMessageContaining("opentmf.security.endpoint");
  }

  @ParameterizedTest
  @EnumSource(EndpointMethod.class)
  void toHttpMethod_mapsOntoSpringsOwnConstant(EndpointMethod method) {
    assertThat(method.toHttpMethod()).isEqualTo(HttpMethod.valueOf(method.name()));
  }

  private static Endpoint bind(String method) {
    MapConfigurationPropertySource source = new MapConfigurationPropertySource(
        Map.of("opentmf.security.endpoint.method", method,
            "opentmf.security.endpoint.path", "/car"));
    return new Binder(source)
        .bind("opentmf.security.endpoint", Bindable.of(Endpoint.class))
        .get();
  }
}
