package org.opentmf.security.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opentmf.security.model.OpenTmfSecurityProperties;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

class UniqueBeanResolverTest {

  private ListAppender<ILoggingEvent> appender;
  private Logger resolverLogger;
  private DefaultListableBeanFactory beanFactory;

  @BeforeEach
  void setUp() {
    resolverLogger = (Logger) LoggerFactory.getLogger(UniqueBeanResolver.class);
    appender = new ListAppender<>();
    appender.start();
    resolverLogger.addAppender(appender);
    beanFactory = new DefaultListableBeanFactory();
  }

  @AfterEach
  void tearDown() {
    resolverLogger.detachAppender(appender);
    appender.stop();
  }

  @Test
  void resolveUnique_withoutCandidates_returnsNullWithoutLogging() {
    AuthenticationEntryPoint resolved =
        UniqueBeanResolver.resolveUnique(provider(), AuthenticationEntryPoint.class);

    assertNull(resolved);
    assertEquals(0, appender.list.size());
  }

  @Test
  void resolveUnique_withSingleCandidate_returnsItAndLogsInfo() {
    AuthenticationEntryPoint entryPoint = new FirstEntryPoint();
    beanFactory.registerSingleton("entryPoint", entryPoint);

    AuthenticationEntryPoint resolved =
        UniqueBeanResolver.resolveUnique(provider(), AuthenticationEntryPoint.class);

    assertSame(entryPoint, resolved);
    List<ILoggingEvent> infos = events(Level.INFO);
    assertEquals(1, infos.size());
    assertTrue(infos.get(0).getFormattedMessage().contains(FirstEntryPoint.class.getName()));
  }

  @Test
  void resolveUnique_withPrimaryAmongCandidates_returnsThePrimary() {
    AuthenticationEntryPoint primary = new FirstEntryPoint();
    RootBeanDefinition primaryDefinition =
        new RootBeanDefinition(AuthenticationEntryPoint.class, () -> primary);
    primaryDefinition.setPrimary(true);
    beanFactory.registerBeanDefinition("primaryEntryPoint", primaryDefinition);
    beanFactory.registerBeanDefinition("secondaryEntryPoint",
        new RootBeanDefinition(AuthenticationEntryPoint.class, SecondEntryPoint::new));

    AuthenticationEntryPoint resolved =
        UniqueBeanResolver.resolveUnique(provider(), AuthenticationEntryPoint.class);

    assertSame(primary, resolved);
    assertEquals(1, events(Level.INFO).size());
    assertEquals(0, events(Level.WARN).size());
  }

  @Test
  void resolveUnique_withAmbiguousCandidates_returnsNullAndWarnsNamingAllCandidates() {
    beanFactory.registerSingleton("firstEntryPoint", new FirstEntryPoint());
    beanFactory.registerSingleton("secondEntryPoint", new SecondEntryPoint());

    AuthenticationEntryPoint resolved =
        UniqueBeanResolver.resolveUnique(provider(), AuthenticationEntryPoint.class);

    assertNull(resolved);
    List<ILoggingEvent> warnings = events(Level.WARN);
    assertEquals(1, warnings.size());
    String message = warnings.get(0).getFormattedMessage();
    assertTrue(message.contains(FirstEntryPoint.class.getName()));
    assertTrue(message.contains(SecondEntryPoint.class.getName()));
    assertTrue(message.contains("@Primary"));
  }

  @Test
  void resolveUnique_reportsTheRequestedTypeName() {
    beanFactory.registerSingleton("entryPoint", new FirstEntryPoint());

    UniqueBeanResolver.resolveUnique(provider(), AuthenticationEntryPoint.class);

    assertTrue(events(Level.INFO).get(0).getFormattedMessage()
        .contains(AuthenticationEntryPoint.class.getSimpleName()));
  }

  @Test
  void resolveUnique_withUnrelatedBeans_returnsNull() {
    beanFactory.registerSingleton("unrelated", new OpenTmfSecurityProperties());

    assertNull(UniqueBeanResolver.resolveUnique(provider(), AuthenticationEntryPoint.class));
  }

  private ObjectProvider<AuthenticationEntryPoint> provider() {
    return beanFactory.getBeanProvider(AuthenticationEntryPoint.class);
  }

  private List<ILoggingEvent> events(Level level) {
    return appender.list.stream().filter(event -> event.getLevel() == level).toList();
  }

  static class FirstEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
        AuthenticationException authException) {
      // no-op test double
    }
  }

  static class SecondEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
        AuthenticationException authException) {
      // no-op test double
    }
  }
}
