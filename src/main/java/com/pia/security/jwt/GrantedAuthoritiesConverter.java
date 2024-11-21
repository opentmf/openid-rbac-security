package com.pia.security.jwt;

import static com.pia.security.jwt.JwtUtil.extractNestedClaimValuesAsList;

import java.util.Collection;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * @author Gokhan Demir
 */
@Slf4j
@RequiredArgsConstructor
public class GrantedAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

  private final String authoritiesClaimName;

  @Override
  public Collection<GrantedAuthority> convert(Jwt jwt) {
    return extractNestedClaimValuesAsList(jwt, authoritiesClaimName)
        .stream().map(SimpleGrantedAuthority::new).collect(Collectors.toSet());
  }
}
