/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.druid.security.athenz;

import com.fasterxml.jackson.annotation.JacksonInject;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.yahoo.athenz.zpe.ZpeClient;
import com.yahoo.athenz.zpe.ZpeConsts;
import com.yahoo.athenz.zpe.match.ZpeMatch;
import com.yahoo.rdl.Struct;
import org.apache.druid.java.util.common.logger.Logger;
import org.apache.druid.server.security.Access;
import org.apache.druid.server.security.Action;
import org.apache.druid.server.security.AuthenticationResult;
import org.apache.druid.server.security.Authorizer;
import org.apache.druid.server.security.Resource;

import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.stream.Stream;

@JsonTypeName("athenz")
public class AthenzAuthorizer implements Authorizer
{
  private static final Access DENY = new Access(false);
  private static final Access ALLOW = new Access(true);
  private static final Logger log = new Logger(AthenzAuthorizer.class);

  private final ZpeClient zpeClient;
  private final String provider;

  @JsonCreator
  public AthenzAuthorizer(
      @JacksonInject ZpeClient zpeClient,
      @JsonProperty("provider") String provider
  )
  {
    this.zpeClient = zpeClient;
    this.provider = provider;
  }

  @Override
  public Access authorize(
      AuthenticationResult authenticationResult,
      Resource resource,
      Action action
  )
  {
    if (!Objects.equals(AthenzUtils.getDomain(authenticationResult), provider)) {
      log.debug("Domain is not matched to %s: AuthenticationResult: %s", provider, authenticationResult);
      return DENY;
    }

    List<String> roles = AthenzUtils.getRoles(authenticationResult);

    Optional<Struct> matched;

    matched = getAssertions(zpeClient.getRoleDenyAssertions(provider), roles).findFirst();
    if (matched.isPresent()) {
      log.debug("Matched: %s, AuthenticationResult: %s", matched.get(), authenticationResult);
      return DENY;
    }

    matched = getAssertions(zpeClient.getRoleAllowAssertions(provider), roles).findFirst();
    if (matched.isPresent()) {
      log.debug("Matched: %s, AuthenticationResult: %s", matched.get(), authenticationResult);
      return ALLOW;
    }

    Predicate<Struct> resourceMatcher = getResourceMatcher(resource);
    Predicate<Struct> actionMatcher = getActionMatcher(action);

    matched = getAssertions(zpeClient.getWildcardDenyAssertions(provider), roles)
        .filter(resourceMatcher)
        .filter(actionMatcher)
        .findFirst();
    if (matched.isPresent()) {
      log.debug("Matched: %s, AuthenticationResult: %s", matched.get(), authenticationResult);
      return DENY;
    }

    matched = getAssertions(zpeClient.getWildcardAllowAssertions(provider), roles)
        .filter(resourceMatcher)
        .filter(actionMatcher)
        .findFirst();
    if (matched.isPresent()) {
      log.debug("Matched: %s, AuthenticationResult: %s", matched.get(), authenticationResult);
      return ALLOW;
    }

    log.debug("No matched assertions: AuthentcationResult: %s", authenticationResult);
    return DENY;
  }

  private Predicate<Struct> getResourceMatcher(Resource resource)
  {
    String type = resource.getType().name().toLowerCase(Locale.ENGLISH);
    String name = resource.getName().toLowerCase(Locale.ENGLISH);
    return getMatcher(ZpeConsts.ZPE_RESOURCE_MATCH_STRUCT, type + "-" + name);
  }

  private Predicate<Struct> getActionMatcher(Action action)
  {
    String value = action.toString().toLowerCase(Locale.ENGLISH);
    return getMatcher(ZpeConsts.ZPE_ACTION_MATCH_STRUCT, value);
  }

  private Predicate<Struct> getMatcher(String key, String value)
  {
    return assertion -> {
      ZpeMatch matcher = (ZpeMatch) assertion.get(key);
      return matcher.matches(value);
    };
  }

  private Stream<Struct> getAssertions(Map<String, List<Struct>> map, List<String> roles)
  {
    if (map == null) {
      return Stream.empty();
    }

    return roles
        .stream()
        .flatMap(role -> map.getOrDefault(role, Collections.emptyList()).stream());
  }

}
