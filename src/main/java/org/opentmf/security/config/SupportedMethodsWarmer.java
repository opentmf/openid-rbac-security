package org.opentmf.security.config;

import java.util.concurrent.atomic.AtomicReference;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.boot.web.server.context.WebServerInitializedEvent;
import org.springframework.context.event.EventListener;

/**
 * Warms one chain's supported-methods resolver off the request path, on whichever startup
 * event reaches its context: the main application context sees {@link ApplicationReadyEvent}
 * (and its servers' {@link WebServerInitializedEvent}s), while a management child context sees
 * only its own {@link WebServerInitializedEvent}. Warming is idempotent and failure-tolerant —
 * see the resolvers' {@code warmUp()} — so firing on both events, for whichever server, is
 * deliberately unconditional: the cost is a no-op, and a guard would be one more thing to keep
 * correct in four places.
 *
 * <p>One shared component instead of a listener per auto-configuration, so the warm-up contract
 * lives — and can change — in exactly one place.
 *
 * @author Gokhan Demir
 */
public class SupportedMethodsWarmer {

  private final AtomicReference<Runnable> target = new AtomicReference<>();

  /** Names the resolver to warm; a chain built without method semantics never calls this. */
  public void register(Runnable warmUp) {
    target.set(warmUp);
  }

  @EventListener(ApplicationReadyEvent.class)
  void onApplicationReady() {
    warm();
  }

  @EventListener(WebServerInitializedEvent.class)
  void onWebServerInitialized() {
    warm();
  }

  private void warm() {
    Runnable warmUp = target.get();
    if (warmUp != null) {
      warmUp.run();
    }
  }
}
