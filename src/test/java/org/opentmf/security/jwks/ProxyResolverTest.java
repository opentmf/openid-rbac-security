package org.opentmf.security.jwks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URI;
import java.util.Map;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * The proxy precedence: the issuer's own property, then the JVM's properties, then the
 * environment with its exclusions, then direct.
 *
 * @author Gokhan Demir
 */
class ProxyResolverTest {

  private static final URI JWKS = URI.create("https://idp.example.test/realms/dnms/certs");
  private static final UnaryOperator<String> NO_ENVIRONMENT = name -> null;

  @AfterEach
  void clearJvmProxy() {
    System.clearProperty("https.proxyHost");
    System.clearProperty("https.proxyPort");
    System.clearProperty("http.nonProxyHosts");
  }

  @Test
  void nothingConfigured_isDirect() {
    assertThat(ProxyResolver.resolve(JWKS, null, NO_ENVIRONMENT)).isSameAs(Proxy.NO_PROXY);
  }

  @Test
  void theIssuersOwnProperty_winsOverEverything() {
    System.setProperty("https.proxyHost", "jvm.proxy");
    System.setProperty("https.proxyPort", "3128");
    UnaryOperator<String> env = environment(Map.of("HTTPS_PROXY", "http://env.proxy:8080"));

    Proxy proxy = ProxyResolver.resolve(JWKS, "issuer.proxy:9000", env);

    assertThat(address(proxy)).isEqualTo("issuer.proxy:9000");
  }

  @Test
  void theJvmProperties_winOverTheEnvironment() {
    System.setProperty("https.proxyHost", "jvm.proxy");
    System.setProperty("https.proxyPort", "3128");
    UnaryOperator<String> env = environment(Map.of("HTTPS_PROXY", "http://env.proxy:8080"));

    assertThat(address(ProxyResolver.resolve(JWKS, null, env))).isEqualTo("jvm.proxy:3128");
  }

  @Test
  void theJvmNonProxyHosts_areHonoured() {
    System.setProperty("https.proxyHost", "jvm.proxy");
    System.setProperty("https.proxyPort", "3128");
    System.setProperty("http.nonProxyHosts", "*.example.test");

    assertThat(ProxyResolver.resolve(JWKS, null, NO_ENVIRONMENT)).isSameAs(Proxy.NO_PROXY);
  }

  @ParameterizedTest
  @ValueSource(strings = {"HTTPS_PROXY", "https_proxy"})
  void theEnvironment_isReadInEitherCase(String variable) {
    UnaryOperator<String> env = environment(Map.of(variable, "http://env.proxy:8080"));

    assertThat(address(ProxyResolver.resolve(JWKS, null, env))).isEqualTo("env.proxy:8080");
  }

  @Test
  void aPlainHttpUrl_readsHttpProxy() {
    UnaryOperator<String> env = environment(Map.of(
        "HTTPS_PROXY", "http://secure.proxy:8080", "HTTP_PROXY", "plain.proxy:8081"));

    Proxy proxy = ProxyResolver.resolve(URI.create("http://idp.example.test/certs"), null, env);

    assertThat(address(proxy)).isEqualTo("plain.proxy:8081");
  }

  @ParameterizedTest
  @ValueSource(strings = {
      "idp.example.test", ".example.test", "example.test", "other.test, example.test", "*"})
  void noProxy_excludesTheHost(String noProxy) {
    UnaryOperator<String> env =
        environment(Map.of("HTTPS_PROXY", "http://env.proxy:8080", "NO_PROXY", noProxy));

    assertThat(ProxyResolver.resolve(JWKS, null, env)).isSameAs(Proxy.NO_PROXY);
  }

  @Test
  void noProxy_doesNotExcludeAnUnrelatedHost() {
    UnaryOperator<String> env =
        environment(Map.of("HTTPS_PROXY", "http://env.proxy:8080", "no_proxy", "internal.test"));

    assertThat(address(ProxyResolver.resolve(JWKS, null, env))).isEqualTo("env.proxy:8080");
  }

  @ParameterizedTest
  @ValueSource(strings = {"proxy", "proxy:", ":8080", "proxy:port"})
  void aMalformedProxy_isANamedError(String value) {
    assertThatThrownBy(() -> ProxyResolver.resolve(JWKS, value, NO_ENVIRONMENT))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("the issuer's proxy property");
  }

  private static UnaryOperator<String> environment(Map<String, String> variables) {
    return variables::get;
  }

  private static String address(Proxy proxy) {
    InetSocketAddress address = (InetSocketAddress) proxy.address();
    return address.getHostString() + ":" + address.getPort();
  }
}
