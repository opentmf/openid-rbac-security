package org.opentmf.security;

import static org.opentmf.security.util.TokenUtil.READ_TOKEN;
import static org.opentmf.security.util.TokenUtil.WRITE_TOKEN;

import org.springframework.test.context.ActiveProfiles;

@ActiveProfiles({"reactive", "local"})
class ReactiveControllerLocalJwkSetIT extends BaseReactiveIT{

  @Override
  String getToken(String scope) {
    return switch (scope) {
      case "read" -> READ_TOKEN;
      case "write" -> WRITE_TOKEN;
      default -> throw new IllegalArgumentException("Unsupported token scope: " + scope);
    };
  }
}
