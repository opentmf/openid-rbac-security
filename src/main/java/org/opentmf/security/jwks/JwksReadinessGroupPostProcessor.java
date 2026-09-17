package org.opentmf.security.jwks;

import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.boot.actuate.endpoint.SecurityContext;
import org.springframework.boot.health.actuate.endpoint.AdditionalHealthEndpointPath;
import org.springframework.boot.health.actuate.endpoint.HealthEndpointGroup;
import org.springframework.boot.health.actuate.endpoint.HealthEndpointGroups;
import org.springframework.boot.health.actuate.endpoint.HealthEndpointGroupsPostProcessor;
import org.springframework.boot.health.actuate.endpoint.HttpCodeStatusMapper;
import org.springframework.boot.health.actuate.endpoint.StatusAggregator;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;

/**
 * Makes the {@code jwks} contributor a member of the {@code readiness} health group, without
 * the adopter touching {@code management.endpoint.health.group.readiness.include}.
 *
 * <p>Independent of the order the post-processors run in — Boot's own probes post-processor
 * sits at the same lowest precedence, and bean registration order is not a contract. When the
 * readiness group already exists it is wrapped and keeps its own aggregator, status mapper,
 * detail policy and additional path; only its membership widens. When it does not exist yet and
 * Kubernetes probes are enabled ({@code management.endpoint.health.probes.enabled}, Boot's
 * default), the group is created here with exactly the members Boot would give it plus
 * {@code jwks}, and Boot's post-processor then keeps it as a pre-configured group. With probes
 * disabled nothing is created; the contributor is still under {@code /actuator/health}.
 *
 * @author Gokhan Demir
 */
@Order(Ordered.LOWEST_PRECEDENCE)
public class JwksReadinessGroupPostProcessor implements HealthEndpointGroupsPostProcessor {

  static final String READINESS = "readiness";
  static final String CONTRIBUTOR = "jwks";
  static final String READINESS_STATE = "readinessState";

  /** The contributor and, as the endpoint asks for them, its per-issuer components. */
  static boolean jwks(String name) {
    return CONTRIBUTOR.equals(name) || name.startsWith(CONTRIBUTOR + "/");
  }

  private final boolean probesEnabled;

  public JwksReadinessGroupPostProcessor(Environment environment) {
    this.probesEnabled = !"false".equalsIgnoreCase(
        environment.getProperty("management.endpoint.health.probes.enabled"));
  }

  @Override
  public HealthEndpointGroups postProcessHealthEndpointGroups(HealthEndpointGroups groups) {
    HealthEndpointGroup readiness = groups.get(READINESS);
    if (readiness != null && readiness.isMember(CONTRIBUTOR)) {
      return groups;
    }
    if (readiness == null && !probesEnabled) {
      return groups;
    }
    Map<String, HealthEndpointGroup> additional = new LinkedHashMap<>();
    for (String name : groups.getNames()) {
      HealthEndpointGroup group = groups.get(name);
      if (group != null && group != groups.getPrimary()) {
        additional.put(name, READINESS.equals(name) ? new WithJwks(group) : group);
      }
    }
    if (readiness == null) {
      additional.put(READINESS, new ProbeGroupWithJwks());
    }
    return HealthEndpointGroups.of(groups.getPrimary(), additional);
  }

  /** The readiness probe group as Boot creates it — status only — plus {@code jwks}. */
  private static final class ProbeGroupWithJwks implements HealthEndpointGroup {

    @Override
    public boolean isMember(String name) {
      return READINESS_STATE.equals(name) || jwks(name);
    }

    @Override
    public boolean showComponents(SecurityContext securityContext) {
      return false;
    }

    @Override
    public boolean showDetails(SecurityContext securityContext) {
      return false;
    }

    @Override
    public StatusAggregator getStatusAggregator() {
      return StatusAggregator.getDefault();
    }

    @Override
    public HttpCodeStatusMapper getHttpCodeStatusMapper() {
      return HttpCodeStatusMapper.getDefault();
    }

    @Override
    public AdditionalHealthEndpointPath getAdditionalPath() {
      return null;
    }
  }

  /** The readiness group as it was, plus {@code jwks}. */
  private record WithJwks(HealthEndpointGroup delegate) implements HealthEndpointGroup {

    @Override
    public boolean isMember(String name) {
      return jwks(name) || delegate.isMember(name);
    }

    @Override
    public boolean showComponents(SecurityContext securityContext) {
      return delegate.showComponents(securityContext);
    }

    @Override
    public boolean showDetails(SecurityContext securityContext) {
      return delegate.showDetails(securityContext);
    }

    @Override
    public StatusAggregator getStatusAggregator() {
      return delegate.getStatusAggregator();
    }

    @Override
    public HttpCodeStatusMapper getHttpCodeStatusMapper() {
      return delegate.getHttpCodeStatusMapper();
    }

    @Override
    public AdditionalHealthEndpointPath getAdditionalPath() {
      return delegate.getAdditionalPath();
    }
  }
}
