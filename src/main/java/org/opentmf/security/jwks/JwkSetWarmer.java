package org.opentmf.security.jwks;

import java.util.List;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.opentmf.security.model.JwksStartupFailure;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;

/**
 * Loads every issuer's signing keys once the application is ready, so the first bearer request
 * finds them cached instead of fetching them itself. Under {@link JwksStartupFailure#WARN} the
 * loads run on a background thread and readiness is not delayed; under
 * {@link JwksStartupFailure#FAIL} they run inline and the application stops, naming the
 * issuers, when none of them could be loaded.
 *
 * <p>One bean per application, in the main context; the management port shares the same
 * decoders and so the same keys, and never warms up on its own.
 *
 * @author Gokhan Demir
 */
@Slf4j
@RequiredArgsConstructor
public class JwkSetWarmer {

  private final List<IssuerKeys> issuers;
  private final JwksStartupFailure policy;

  @EventListener(ApplicationReadyEvent.class)
  void onApplicationReady() {
    if (issuers.isEmpty()) {
      return;
    }
    if (policy == JwksStartupFailure.FAIL) {
      warmUpOrFail();
      return;
    }
    Thread thread = new Thread(this::warmUpAll, "jwks-warm-up");
    thread.setDaemon(true);
    thread.start();
  }

  /** Loads every issuer; returns how many succeeded. Visible for tests. */
  int warmUpAll() {
    int loaded = 0;
    for (IssuerKeys keys : issuers) {
      if (keys.warmUp()) {
        loaded++;
      }
    }
    return loaded;
  }

  private void warmUpOrFail() {
    if (warmUpAll() == 0) {
      throw new IllegalStateException(
          "The signing keys of no trusted issuer could be loaded ("
              + issuers.stream().map(IssuerKeys::name).collect(Collectors.joining(", "))
              + ") and opentmf.security.jwks.on-startup-failure is FAIL. See the warnings"
              + " above for each issuer's cause.");
    }
  }
}
