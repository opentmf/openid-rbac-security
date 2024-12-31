package com.pia.security.util;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import com.nimbusds.jose.util.Resource;
import com.pia.security.jwt.JwtService;
import com.pia.security.model.PiaSecurityProperties;
import java.io.IOException;
import java.net.URL;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

/**
 * @author Gokhan Demir
 */
@SpringBootTest
@EnableConfigurationProperties(PiaSecurityProperties.class)
@ActiveProfiles("servlet-local")
class ServletResourceRetrieverLocalIT {

  @Autowired
  private PiaSecurityProperties properties;

  @Autowired
  private JwtService jwtService;

  @Test
  void testRetrieveResource() throws IOException {
    ServletResourceRetriever servletResourceRetriever = new ServletResourceRetriever();
    URL url = properties.getJwkSetUri().getURL();
    Resource resource = servletResourceRetriever.retrieveResource(url);
    Assertions.assertFalse(resource.getContent().isBlank());
    Assertions.assertEquals(APPLICATION_JSON_VALUE, resource.getContentType());
    Assertions.assertTrue(jwtService.isExpiredToken(TokenUtil.EXPIRED_READER_TOKEN));
  }
}
