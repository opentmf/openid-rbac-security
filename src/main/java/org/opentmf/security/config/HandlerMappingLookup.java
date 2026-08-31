package org.opentmf.security.config;

import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Stream;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.function.SingletonSupplier;

/**
 * Captures the handler-mapping beans once, lazily, and can be primed off the request path.
 *
 * <p>Shared by both stacks' resolvers, which is why it is generic over the mapping type and
 * names no web type of its own: the servlet and reactive halves of this library must stay
 * loadable when the other stack is absent from the classpath.
 *
 * @param <T> the stack's {@code RequestMappingInfoHandlerMapping} type
 * @author Gokhan Demir
 */
@Slf4j
class HandlerMappingLookup<T> {

  private final Supplier<List<T>> beans;

  HandlerMappingLookup(Supplier<Stream<T>> handlerMappings) {
    this.beans = SingletonSupplier.of(() -> {
      List<T> list = handlerMappings.get().toList();
      log.debug("Captured {} handler mappings for HTTP method resolution.", list.size());
      return list;
    });
  }

  List<T> get() {
    return beans.get();
  }

  /**
   * Performs the lazy lookup now, so the first denial does not pay for it — on the reactive
   * stack that cost would land on a Netty event-loop thread. A failure is logged at debug and
   * the lookup is simply retried on first use, exactly as if this had not been called.
   */
  void warmUp() {
    try {
      beans.get();
    } catch (RuntimeException | LinkageError ex) {
      log.debug("Could not warm up the handler-mapping lookup — the first denial retries.", ex);
    }
  }
}
