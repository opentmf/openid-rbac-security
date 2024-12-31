package com.pia.security.util;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import com.nimbusds.jose.util.Resource;
import com.nimbusds.jose.util.ResourceRetriever;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import org.springframework.util.ResourceUtils;
import org.springframework.web.client.RestTemplate;

/**
 * A custom resource retriever to support local jwk-set-uri
 * in servlet applications.
 *
 * @author Gokhan Demir
 */
public class ServletResourceRetriever implements ResourceRetriever {

  @Override
  public Resource retrieveResource(java.net.URL url) {
    try {
      String content = ResourceUtils.isFileURL(url)
          ? contents(new FileInputStream(ResourceUtils.getFile(url)))
          : retrieve(url);
      return new Resource(content, APPLICATION_JSON_VALUE);
    } catch (FileNotFoundException e) {
      throw new IllegalArgumentException("File not found: " + url, e);
    }
  }

  private static String contents(InputStream inputStream) {
    try {
      var result = new ByteArrayOutputStream();
      var buffer = new byte[1024];
      for (int length; (length = inputStream.read(buffer)) != -1; ) {
        result.write(buffer, 0, length);
      }
      return result.toString(StandardCharsets.UTF_8);
    } catch (IOException e) {
      throw new IllegalArgumentException(e);
    }
  }

  private static final RestTemplate REST_TEMPLATE = new RestTemplate();

  private static String retrieve(URL url) {
    // GD: we need to implement retry mechanism
    return REST_TEMPLATE.getForEntity(url.toString(), String.class).getBody();
  }
}
