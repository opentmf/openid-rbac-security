package org.opentmf.security.config;

import java.util.List;
import java.util.Locale;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.opentmf.security.model.EndpointMethod;
import org.opentmf.security.model.OpenTmfSecurityProperties;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.core.env.Environment;

/**
 * Fails startup when an access rule's {@code method} is not spelled exactly as its enum
 * constant.
 *
 * <p>Boot's relaxed enum binding canonicalizes a value by dropping every character that is not
 * a letter or digit and ignoring case — so {@code get}, {@code G-E-T} and {@code "GET "} all
 * bind to {@code GET}. That leniency is precisely the hazard here: before 3.0.0 such values
 * bound through the case- and string-preserving {@code HttpMethod.valueOf}, and both stacks'
 * matchers compare the verb by exact string, so the rule silently never matched — it was dead,
 * and its path fell through to the catch-all. Lenient binding would bring such a rule to life
 * on upgrade with no warning; for {@code allowed-endpoints}, anonymous {@code permitAll}
 * appearing out of a line that never did anything. So a dead rule may only come alive after
 * someone has read it: any spelling that lenient binding would accept but 2.x would not have
 * matched is rejected with a message naming the entry. A value lenient binding rejects too
 * ({@code HEAD}, a typo) is left to the real bind and its own failure.
 *
 * <p>This is a startup check over the raw configuration rather than a binding
 * {@code Converter}, deliberately: a converter registered via
 * {@code @ConfigurationPropertiesBinding} that rejects a value does not fail the bind — Boot
 * falls through to the next conversion service, whose lenient enum support accepts it, and the
 * rejection evaporates. Reading the raw strings from the {@code Environment} sees the exact
 * spelling before any conversion touches it, across every relaxed form of the property names.
 * The property tree it walks is named once, in
 * {@link OpenTmfSecurityProperties#METHOD_RULE_LISTS}, next to the fields it mirrors.
 *
 * @author Gokhan Demir
 */
@RequiredArgsConstructor
public class EndpointMethodCaseGuard implements InitializingBean {

  private static final List<String> SECTIONS =
      List.of(OpenTmfSecurityProperties.PREFIX, OpenTmfSecurityProperties.PREFIX + ".management");

  private final Environment environment;

  @Override
  public void afterPropertiesSet() {
    Binder binder = Binder.get(environment);
    for (String section : SECTIONS) {
      for (String ruleList : OpenTmfSecurityProperties.METHOD_RULE_LISTS) {
        check(binder, section + "." + ruleList);
      }
    }
  }

  private void check(Binder binder, String property) {
    List<RawAccessRule> rules =
        binder.bind(property, Bindable.listOf(RawAccessRule.class)).orElseGet(List::of);
    for (int i = 0; i < rules.size(); i++) {
      String method = rules.get(i).getMethod();
      if (wouldSilentlyActivate(method)) {
        throw new IllegalStateException(
            property + "[" + i + "].method: '" + method + "' must be spelled exactly '"
                + leniently(method).name() + "'. On releases before 3.0.0 this spelling never"
                + " matched any request, so the rule was dead; binding it leniently would"
                + " silently activate it. Review the rule and fix the spelling if it is"
                + " intended.");
      }
    }
  }

  /**
   * Whether lenient binding would accept the value even though it is not the exact constant
   * name — the dead-rule-comes-alive case.
   */
  private static boolean wouldSilentlyActivate(String method) {
    if (method == null || isExactConstant(method)) {
      return false;
    }
    return leniently(method) != null;
  }

  private static boolean isExactConstant(String method) {
    for (EndpointMethod value : EndpointMethod.values()) {
      if (value.name().equals(method)) {
        return true;
      }
    }
    return false;
  }

  /** Resolves the value the way Boot's lenient enum binding would, or {@code null}. */
  private static EndpointMethod leniently(String method) {
    String canonical = canonical(method);
    for (EndpointMethod value : EndpointMethod.values()) {
      if (canonical(value.name()).equals(canonical)) {
        return value;
      }
    }
    return null;
  }

  /** Boot's canonical form: letters and digits only, lower-cased. */
  private static String canonical(String value) {
    StringBuilder canonical = new StringBuilder(value.length());
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      if (Character.isLetterOrDigit(c)) {
        canonical.append(Character.toLowerCase(c));
      }
    }
    return canonical.toString().toLowerCase(Locale.ROOT);
  }

  /** The rule bound shallowly: the method stays a raw string, so its spelling survives. */
  @Getter
  @Setter
  public static class RawAccessRule {
    private String method;
  }
}
