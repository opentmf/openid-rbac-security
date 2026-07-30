package org.opentmf.security.util;

import static org.opentmf.security.util.ResourceRetrieverSupport.contents;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import com.nimbusds.jose.util.Resource;
import com.nimbusds.jose.util.ResourceRetriever;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import org.springframework.util.ResourceUtils;

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
      String content = contents(new FileInputStream(ResourceUtils.getFile(url)));
      return new Resource(content, APPLICATION_JSON_VALUE);
    } catch (FileNotFoundException e) {
      throw new IllegalArgumentException("File not found: " + url, e);
    }
  }
}
