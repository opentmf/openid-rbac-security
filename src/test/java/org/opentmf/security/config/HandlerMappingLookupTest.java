package org.opentmf.security.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * The lookup is generic and stack-free, so it is exercised here with plain types: what matters
 * is the caching contract, not the mapping type.
 *
 * @author Gokhan Demir
 */
class HandlerMappingLookupTest {

  @Test
  void entries_pairEachMappingWithItsInfos() {
    var lookup = new HandlerMappingLookup<String, Integer>(
        () -> Stream.of("a", "b"), mapping -> List.of(mapping.length()));

    var entries = lookup.entries();

    assertThat(entries).hasSize(2);
    assertThat(entries.get(0).mapping()).isEqualTo("a");
    assertThat(entries.get(0).infos()).containsExactly(1);
  }

  @Test
  void entries_withinTheCacheWindow_doNotReReadTheInfos() {
    AtomicInteger reads = new AtomicInteger();
    var lookup = new HandlerMappingLookup<String, Integer>(
        () -> Stream.of("a"), mapping -> List.of(reads.incrementAndGet()));

    assertThat(lookup.entries()).isSameAs(lookup.entries());
    assertThat(reads).hasValue(1);
  }

  @Test
  void theBeanLookup_happensOnceEvenAcrossCacheRefreshes() {
    AtomicInteger beanLookups = new AtomicInteger();
    var lookup = new HandlerMappingLookup<String, Integer>(
        () -> {
          beanLookups.incrementAndGet();
          return Stream.of("a");
        },
        mapping -> List.of(1));

    lookup.warmUp();
    lookup.entries();

    assertThat(beanLookups).hasValue(1);
  }

  @Test
  void warmUp_swallowsAFailingLookup_soADenialRetriesIt() {
    AtomicInteger attempts = new AtomicInteger();
    var lookup = new HandlerMappingLookup<String, Integer>(
        () -> {
          attempts.incrementAndGet();
          throw new IllegalStateException("not ready yet");
        },
        mapping -> List.of(1));

    assertThatCode(lookup::warmUp).doesNotThrowAnyException();
    assertThatThrownBy(lookup::entries).isInstanceOf(IllegalStateException.class);
    assertThat(attempts).hasValue(2);
  }
}
