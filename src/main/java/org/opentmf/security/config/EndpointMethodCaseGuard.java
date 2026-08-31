package org.opentmf.security.config;

import java.util.List;
import java.util.Locale;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.core.env.Environment;

/**
 * Fails startup when an access rule's {@code method} is not written upper-case.
 *
 * <p>Boot's relaxed enum binding would happily accept {@code get} — and that leniency is
 * precisely the hazard. Before 3.0.0 the value bound through {@code HttpMethod.valueOf}, which
 * preserves case, and both stacks' matchers compare the verb by exact string, so a
 * non-upper-case rule silently never matched: it was dead, and its path fell through to the
 * catch-all. Lenient binding would bring such a rule to life on upgrade with no warning — for
 * {@code allowed-endpoints}, anonymous {@code permitAll} appearing out of a line that never did
 * anything. So a dead rule may only come alive after someone has read it.
 *
 * <p>This is a startup check over the raw configuration rather than a binding
 * {@code Converter}, deliberately: a converter registered via
 * {@code @ConfigurationPropertiesBinding} that rejects a value does not fail the bind — Boot
 * falls through to the next conversion service, whose lenient enum support accepts it, and the
 * rejection evaporates. Reading the raw strings from the {@code Environment} sees the case
 * before any conversion touches it, across every relaxed spelling of the property names.
 *
 * @author Gokhan Demir
 */
@RequiredArgsConstructor
public class EndpointMethodCaseGuard implements InitializingBean {

  private static final List<String> SECTIONS =
      List.of("opentmf.security", "opentmf.security.management");
  private static final List<String> RULE_LISTS = List.of("allowed-endpoints", "secure-endpoints");

  private final Environment environment;

  @Override
  public void afterPropertiesSet() {
    Binder binder = Binder.get(environment);
    for (String section : SECTIONS) {
      for (String ruleList : RULE_LISTS) {
        check(binder, section + "." + ruleList);
      }
    }
  }

  private void check(Binder binder, String property) {
    List<RawAccessRule> rules =
        binder.bind(property, Bindable.listOf(RawAccessRule.class)).orElseGet(List::of);
    for (int i = 0; i < rules.size(); i++) {
      String method = rules.get(i).getMethod();
      if (method != null && !method.equals(method.toUpperCase(Locale.ROOT))) {
        throw new IllegalStateException(
            property + "[" + i + "].method: '" + method + "' must be written upper-case. On"
                + " releases before 3.0.0 a non-upper-case value never matched any request, so"
                + " this rule was dead; binding it leniently would silently activate it. Review"
                + " the rule and write '" + method.toUpperCase(Locale.ROOT)
                + "' if it is intended.");
      }
    }
  }

  /** The rule bound shallowly: the method stays a raw string, so its case survives binding. */
  @Getter
  @Setter
  public static class RawAccessRule {
    private String method;
  }
}
