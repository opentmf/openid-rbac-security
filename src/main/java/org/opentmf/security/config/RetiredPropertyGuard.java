package org.opentmf.security.config;

import java.util.List;
import lombok.RequiredArgsConstructor;
import org.opentmf.security.model.OpenTmfSecurityProperties;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.core.env.Environment;

/**
 * Fails startup when the configuration still sets a property this library has retired.
 *
 * <p>Boot ignores an unknown property without a word, which is the wrong outcome for one that
 * used to change behaviour: {@code unmatched-method-response: deny} was the opt-out from the
 * {@code 405} answer, and a deployment that set it to keep its method surface undisclosed
 * would, on upgrade, start disclosing it with nothing in the log to say so. So the raw
 * configuration is read at startup, across every relaxed spelling of the name and on both
 * sections, and a value that is still there stops the application with a message that says
 * what replaced it. The list of names lives in
 * {@link OpenTmfSecurityProperties#RETIRED_PROPERTIES}, next to the fields it once mirrored.
 *
 * @author Gokhan Demir
 */
@RequiredArgsConstructor
public class RetiredPropertyGuard implements InitializingBean {

  private static final List<String> SECTIONS =
      List.of(OpenTmfSecurityProperties.PREFIX, OpenTmfSecurityProperties.PREFIX + ".management");

  private final Environment environment;

  @Override
  public void afterPropertiesSet() {
    Binder binder = Binder.get(environment);
    for (String section : SECTIONS) {
      for (String retired : OpenTmfSecurityProperties.RETIRED_PROPERTIES) {
        String property = section + "." + retired;
        binder.bind(property, String.class).ifBound(value -> {
          throw new IllegalStateException(
              property + " is set to '" + value + "' but was retired in 3.1.0 and has no"
                  + " effect: the HTTP-status matrix (404 for an unknown path, 405 without"
                  + " Allow for a method the path does not implement, then 401/403) is not"
                  + " configurable. Remove the property.");
        });
      }
    }
  }
}
