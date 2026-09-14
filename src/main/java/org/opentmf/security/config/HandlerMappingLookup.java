package org.opentmf.security.config;

import java.util.Collection;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Stream;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.AnnotationAwareOrderComparator;
import org.springframework.util.function.SingletonSupplier;

/**
 * Captures the handler-mapping beans once, lazily, in the order the dispatcher consults them,
 * and serves the annotation mappings' infos through a briefly cached view.
 *
 * <p>The bean lookup happens once and can be {@linkplain #warmUp() primed} off the request
 * path. The infos are re-read so that mappings registered or removed at runtime are answered
 * for — but reading them costs a locked copy of the entire registry per mapping bean, and the
 * lookup runs on every request, so the read is cached for one second: fresh enough that a
 * runtime-registered mapping is visible almost immediately, cheap enough that a probe storm
 * cannot turn registry copies into a CPU amplifier on, for the reactive stack, an event-loop
 * thread. Mappings that are not annotation-based carry no infos; the resolvers ask them
 * directly, per request.
 *
 * <p>Shared by both stacks' resolvers, which is why it is generic over the mapping and info
 * types and names no web type of its own: the servlet and reactive halves of this library must
 * stay loadable when the other stack is absent from the classpath.
 *
 * @param <T> the stack's {@code HandlerMapping} type
 * @param <I> the stack's {@code RequestMappingInfo} type
 * @author Gokhan Demir
 */
@Slf4j
class HandlerMappingLookup<T, I> {

  private static final long CACHE_NANOS = TimeUnit.SECONDS.toNanos(1);

  private final Supplier<List<T>> beans;
  private final Function<T, Collection<I>> infosOf;
  private final AtomicReference<Cached<T, I>> cached = new AtomicReference<>();

  /**
   * One mapping bean together with the infos it held when the view was taken — empty for a
   * mapping that is not annotation-based.
   */
  record Entry<T, I>(T mapping, Collection<I> infos) {}

  private record Cached<T, I>(List<Entry<T, I>> entries, long takenAtNanos) {}

  HandlerMappingLookup(Supplier<Stream<T>> handlerMappings, Function<T, Collection<I>> infosOf) {
    this.infosOf = infosOf;
    this.beans = SingletonSupplier.of(() -> {
      // The dispatcher's own order: the first mapping to claim a path answers for it.
      List<T> list = handlerMappings.get().sorted(AnnotationAwareOrderComparator.INSTANCE).toList();
      log.debug("Captured {} handler mappings for HTTP method resolution.", list.size());
      return list;
    });
  }

  /** The mapping beans, in dispatch order, with their current infos, at most one second stale. */
  List<Entry<T, I>> entries() {
    Cached<T, I> current = cached.get();
    long now = System.nanoTime();
    if (current != null && now - current.takenAtNanos() < CACHE_NANOS) {
      return current.entries();
    }
    List<Entry<T, I>> fresh = beans.get().stream()
        .map(mapping -> new Entry<>(mapping, infosOf.apply(mapping)))
        .toList();
    cached.set(new Cached<>(fresh, now));
    return fresh;
  }

  /**
   * Performs the lazy bean lookup now, so the first denial does not pay for it — on the
   * reactive stack that cost would land on a Netty event-loop thread. A failure is logged at
   * debug and the lookup is simply retried on first use, exactly as if this had not been
   * called.
   */
  void warmUp() {
    try {
      beans.get();
    } catch (RuntimeException | LinkageError ex) {
      log.debug("Could not warm up the handler-mapping lookup — the first denial retries.", ex);
    }
  }
}
