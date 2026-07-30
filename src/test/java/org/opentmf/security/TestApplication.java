package org.opentmf.security;

import org.opentmf.security.model.TokenProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.actuate.autoconfigure.web.ManagementContextConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigurationExcludeFilter;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.context.TypeExcludeFilter;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.ComponentScan.Filter;
import org.springframework.context.annotation.FilterType;

/**
 * Expanded form of {@code @SpringBootApplication} with one extra component-scan exclusion: this
 * test app lives in {@code org.opentmf.security}, so a plain scan would sweep up the library's
 * {@link ManagementContextConfiguration} classes and register the management-port filter chain in
 * the MAIN context, where its highest-precedence {@code /**} matcher would hijack every main-port
 * request. Real consumers never scan the library's packages, so only this test app needs the
 * filter; the management child context still imports those classes via
 * {@code META-INF/spring/...ManagementContextConfiguration.imports}.
 */
@SpringBootConfiguration
@EnableAutoConfiguration
@ComponentScan(excludeFilters = {
    @Filter(type = FilterType.CUSTOM, classes = TypeExcludeFilter.class),
    @Filter(type = FilterType.CUSTOM, classes = AutoConfigurationExcludeFilter.class),
    @Filter(type = FilterType.ANNOTATION, classes = ManagementContextConfiguration.class)})
@EnableConfigurationProperties(TokenProperties.class)
public class TestApplication {

  public static void main(String[] args) {
    SpringApplication.run(TestApplication.class, args);
  }
}
