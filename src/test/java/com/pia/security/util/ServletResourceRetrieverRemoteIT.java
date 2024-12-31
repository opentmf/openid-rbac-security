package com.pia.security.util;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import com.nimbusds.jose.util.Resource;
import com.pia.security.helper.MockServerUtils;
import com.pia.security.model.PiaSecurityProperties;
import java.io.IOException;
import java.net.URL;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.ActiveProfiles;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

/**
 * @author Gokhan Demir
 */
@SpringBootTest
@EnableConfigurationProperties(PiaSecurityProperties.class)
@ActiveProfiles("servlet")
@ExtendWith(SystemStubsExtension.class)
class ServletResourceRetrieverRemoteIT {

  @Autowired
  private PiaSecurityProperties properties;

  @SystemStub
  private static final EnvironmentVariables STARTUP_ENV_VARIABLES =
      new EnvironmentVariables(
          "PIA_SECURITY_JWK_SET_URI", MockServerUtils.MOCKSERVER_URL
      );

  static {
    MockServerUtils.expectGet("", 1, HttpStatus.OK, "{}");
  }

  @Test
  void testRetrieveResource() throws IOException {
    ServletResourceRetriever servletResourceRetriever = new ServletResourceRetriever();
    URL url = properties.getJwkSetUri().getURL();
    Resource nimbusResource = servletResourceRetriever.retrieveResource(url);
    Assertions.assertFalse(nimbusResource.getContent().isBlank());
    Assertions.assertEquals(APPLICATION_JSON_VALUE, nimbusResource.getContentType());
  }
}
