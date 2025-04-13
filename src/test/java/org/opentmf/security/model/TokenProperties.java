package org.opentmf.security.model;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import java.util.Map;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * @author Gokhan Demir
 */
@Getter
@Setter
@Validated
@ConfigurationProperties(prefix = "token")
public class TokenProperties {

  @NotEmpty private String clientId;
  @NotEmpty private String clientSecret;
  @NotEmpty private Map<String, @Valid UserPass> users;

  @Getter
  @Setter
  public static class UserPass {
    @NotEmpty private String username;
    @NotEmpty private String password;
  }
}
