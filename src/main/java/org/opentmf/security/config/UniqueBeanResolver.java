package org.opentmf.security.config;

import java.util.List;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;

/**
 * Resolves an optional, consumer-supplied customization bean from an {@link ObjectProvider}.
 * Exactly one candidate (or one marked {@code @Primary}) is applied; zero candidates means the
 * Spring Security defaults stay in effect; multiple non-primary candidates are ambiguous, so the
 * library refuses to guess and falls back to the defaults with a WARN.
 *
 * @author Gokhan Demir
 */
@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
final class UniqueBeanResolver {

  static <T> T resolveUnique(ObjectProvider<T> provider, Class<T> type) {
    T bean = provider.getIfUnique();
    if (bean != null) {
      log.info("Applying custom {} to the security filter chain: {}",
          type.getSimpleName(), bean.getClass().getName());
      return bean;
    }
    List<String> candidates =
        provider.stream().map(candidate -> candidate.getClass().getName()).toList();
    if (candidates.size() > 1) {
      log.warn("Found {} candidate {} beans ({}). Mark exactly one of them as @Primary to have it"
              + " applied, or remove the extras. Falling back to the Spring Security default"
              + " 401/403 responses.",
          candidates.size(), type.getSimpleName(), String.join(", ", candidates));
    }
    return null;
  }
}
