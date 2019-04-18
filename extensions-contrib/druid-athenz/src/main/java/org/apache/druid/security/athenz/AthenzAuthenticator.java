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
import com.yahoo.athenz.auth.token.RoleToken;
import com.yahoo.athenz.zpe.pkey.PublicKeyStore;
import org.apache.druid.java.util.common.logger.Logger;
import org.apache.druid.server.security.AuthConfig;
import org.apache.druid.server.security.AuthenticationResult;
import org.apache.druid.server.security.Authenticator;

import javax.annotation.Nullable;
import javax.servlet.DispatcherType;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.PublicKey;
import java.util.EnumSet;
import java.util.Map;

@JsonTypeName("athenz")
public class AthenzAuthenticator implements Authenticator
{
  private static final int DEFAULT_ALLOWED_OFFSET = 300;
  private static final Logger log = new Logger(AthenzAuthenticator.class);

  private final PublicKeyStore keyStore;
  private final String name;
  private final String authorizerName;
  private final int allowedOffset;
  private final boolean allowNoExpiry;

  @JsonCreator
  public AthenzAuthenticator(
      @JacksonInject PublicKeyStore keyStore,
      @JsonProperty("name") String name,
      @JsonProperty("authorizerName") String authorizerName,
      @JsonProperty("allowedOffset") Integer allowedOffset,
      @JsonProperty("allowNoExpiry") boolean allowNoExpiry
  )
  {
    this.keyStore = keyStore;
    this.name = name;
    this.authorizerName = authorizerName;
    this.allowedOffset = allowedOffset == null ? DEFAULT_ALLOWED_OFFSET : allowedOffset;
    this.allowNoExpiry = allowNoExpiry;
  }

  @Override
  public Filter getFilter()
  {
    return new AthenzAuthenticationFilter();
  }

  @Override
  public Class<? extends Filter> getFilterClass()
  {
    return null;
  }

  @Override
  public Map<String, String> getInitParameters()
  {
    return null;
  }

  @Override
  public String getPath()
  {
    return "/*";
  }

  @Override
  public EnumSet<DispatcherType> getDispatcherType()
  {
    return null;
  }

  @Nullable
  @Override
  public String getAuthChallengeHeader()
  {
    return "Athenz";
  }

  @Nullable
  @Override
  public AuthenticationResult authenticateJDBCContext(Map<String, Object> context)
  {
    return null;
  }

  private class AthenzAuthenticationFilter implements Filter
  {
    @Override
    public void init(FilterConfig filterConfig)
    {

    }

    @Override
    public void doFilter(
        ServletRequest servletRequest,
        ServletResponse servletResponse,
        FilterChain filterChain
    ) throws IOException, ServletException
    {
      HttpServletRequest httpReq = (HttpServletRequest) servletRequest;
      HttpServletResponse httpResp = (HttpServletResponse) servletResponse;

      String authHeader = httpReq.getHeader("Athenz-Role-Auth");
      if (authHeader == null) {
        filterChain.doFilter(servletRequest, servletResponse);
        return;
      }

      RoleToken token;
      try {
        token = new RoleToken(authHeader);
      }
      catch (IllegalArgumentException e) {
        httpResp.sendError(HttpServletResponse.SC_UNAUTHORIZED);
        return;
      }

      if (!verify(token)) {
        httpResp.sendError(HttpServletResponse.SC_UNAUTHORIZED);
        return;
      }

      AuthenticationResult authenticationResult = new AuthenticationResult(
          token.getPrincipal(),
          authorizerName,
          name,
          AthenzUtils.getContext(token)
      );
      servletRequest.setAttribute(AuthConfig.DRUID_AUTHENTICATION_RESULT, authenticationResult);
      filterChain.doFilter(servletRequest, servletResponse);
    }

    @Override
    public void destroy()
    {

    }
  }

  private boolean verify(RoleToken roleToken)
  {
    String keyId = roleToken.getKeyId();
    PublicKey key = keyStore.getZtsKey(keyId);
    if (key == null) {
      log.debug("No public key: keyId=%s", keyId);
      return false;
    }

    StringBuilder errMsg = new StringBuilder();
    if (!roleToken.validate(key, allowedOffset, allowNoExpiry, errMsg)) {
      log.debug("Invalid Role Token: %s", errMsg);
      return false;
    }

    return true;
  }
}
