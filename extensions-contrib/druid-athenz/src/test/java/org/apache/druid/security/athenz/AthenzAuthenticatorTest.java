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

import com.yahoo.athenz.auth.token.RoleToken;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.zpe.pkey.PublicKeyStore;
import org.apache.druid.server.security.AuthConfig;
import org.apache.druid.server.security.AuthenticationResult;
import org.easymock.EasyMock;
import org.junit.Test;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

public class AthenzAuthenticatorTest
{

  private static final Class LOADER = AthenzAuthenticatorTest.class;
  private static final PublicKeyStore KEY_STORE = new PublicKeyStore()
  {
    @Override
    public PublicKey getZtsKey(String keyId)
    {
      try {
        switch (keyId) {
          case "0":
            return loadPublicKey("/pub-0.pem");
          case "1":
            return loadPublicKey("/pub-1.pem");
          default:
            return null;
        }
      }
      catch (IOException e) {
        return null;
      }
    }

    @Override
    public PublicKey getZmsKey(String keyId)
    {
      return null;
    }
  };

  private static final AthenzAuthenticator AUTHENTICATOR = new AthenzAuthenticator(
      KEY_STORE,
      "athenz",
      "athenz",
      null,
      false
  );

  private static PrivateKey loadPrivateKey(String name) throws IOException
  {
    InputStream inputStream = LOADER.getResourceAsStream(name);
    if (inputStream == null) {
      throw new NullPointerException();
    }
    try (Reader reader = new InputStreamReader(inputStream, StandardCharsets.UTF_8)) {
      return Crypto.loadPrivateKey(reader);
    }
  }

  private static PublicKey loadPublicKey(String name) throws IOException
  {
    InputStream inputStream = LOADER.getResourceAsStream(name);
    if (inputStream == null) {
      throw new NullPointerException();
    }
    try (Reader reader = new InputStreamReader(inputStream, StandardCharsets.UTF_8)) {
      return Crypto.loadPublicKey(reader);
    }
  }

  @Test
  public void testGoodToken() throws IOException, ServletException
  {
    PrivateKey pri = loadPrivateKey("/pri-0.pem");
    RoleToken token = new RoleToken.Builder("V1", "test", Arrays.asList("user", "admin"))
        .principal("username")
        .keyId("0")
        .build();
    token.sign(pri);

    HttpServletRequest req = EasyMock.createMock(HttpServletRequest.class);
    EasyMock.expect(req.getHeader("Athenz-Role-Auth")).andReturn(token.getSignedToken());
    req.setAttribute(
        AuthConfig.DRUID_AUTHENTICATION_RESULT,
        new AuthenticationResult("username", "athenz", "athenz", AthenzUtils.getContext(token))
    );
    EasyMock.expectLastCall().times(1);
    EasyMock.replay(req);

    HttpServletResponse resp = EasyMock.createMock(HttpServletResponse.class);
    EasyMock.replay(resp);

    FilterChain filterChain = EasyMock.createMock(FilterChain.class);
    filterChain.doFilter(req, resp);
    EasyMock.expectLastCall().times(1);
    EasyMock.replay(filterChain);

    Filter authenticationFilter = AUTHENTICATOR.getFilter();
    authenticationFilter.doFilter(req, resp, filterChain);

    EasyMock.verify(req, resp, filterChain);
  }

  @Test
  public void testBadToken() throws IOException, ServletException
  {
    PrivateKey pri = loadPrivateKey("/pri-1.pem");
    RoleToken token = new RoleToken.Builder("V1", "test", Arrays.asList("user", "admin"))
        .principal("username")
        .keyId("0")
        .build();
    token.sign(pri);

    HttpServletRequest req = EasyMock.createMock(HttpServletRequest.class);
    EasyMock.expect(req.getHeader("Athenz-Role-Auth")).andReturn(token.getSignedToken());
    EasyMock.replay(req);

    HttpServletResponse resp = EasyMock.createMock(HttpServletResponse.class);
    resp.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    EasyMock.expectLastCall().times(1);
    EasyMock.replay(resp);

    FilterChain filterChain = EasyMock.createMock(FilterChain.class);
    EasyMock.replay(filterChain);

    Filter authenticatorFilter = AUTHENTICATOR.getFilter();
    authenticatorFilter.doFilter(req, resp, filterChain);

    EasyMock.verify(req, resp, filterChain);
  }

  @Test
  public void testRecognizedButMalformedAthenzRoleAuthHeader() throws IOException, ServletException
  {
    HttpServletRequest req = EasyMock.createMock(HttpServletRequest.class);
    EasyMock.expect(req.getHeader("Athenz-Role-Auth")).andReturn("malformed Athenz role auth header");
    EasyMock.replay(req);

    HttpServletResponse resp = EasyMock.createMock(HttpServletResponse.class);
    resp.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    EasyMock.expectLastCall().times(1);
    EasyMock.replay(resp);

    FilterChain filterChain = EasyMock.createMock(FilterChain.class);
    EasyMock.replay(filterChain);

    Filter authenticatorFilter = AUTHENTICATOR.getFilter();
    authenticatorFilter.doFilter(req, resp, filterChain);

    EasyMock.verify(req, resp, filterChain);
  }

  @Test
  public void testNoZtsKey() throws IOException, ServletException
  {
    PrivateKey pri = loadPrivateKey("/pri-0.pem");
    RoleToken token = new RoleToken.Builder("V1", "test", Arrays.asList("user", "admin"))
        .principal("username")
        .keyId("2")
        .build();
    token.sign(pri);

    HttpServletRequest req = EasyMock.createMock(HttpServletRequest.class);
    EasyMock.expect(req.getHeader("Athenz-Role-Auth")).andReturn(token.getSignedToken());
    EasyMock.replay(req);

    HttpServletResponse resp = EasyMock.createMock(HttpServletResponse.class);
    resp.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    EasyMock.expectLastCall().times(1);
    EasyMock.replay(resp);

    FilterChain filterChain = EasyMock.createMock(FilterChain.class);
    EasyMock.replay(filterChain);

    Filter authenticatorFilter = AUTHENTICATOR.getFilter();
    authenticatorFilter.doFilter(req, resp, filterChain);

    EasyMock.verify(req, resp, filterChain);
  }

  @Test
  public void testMissingHeader() throws IOException, ServletException
  {
    HttpServletRequest req = EasyMock.createMock(HttpServletRequest.class);
    EasyMock.expect(req.getHeader("Athenz-Role-Auth")).andReturn(null);
    EasyMock.replay(req);

    HttpServletResponse resp = EasyMock.createMock(HttpServletResponse.class);
    EasyMock.replay(resp);

    // Authentication filter should move on to the next filter in the chain without sending a response
    FilterChain filterChain = EasyMock.createMock(FilterChain.class);
    filterChain.doFilter(req, resp);
    EasyMock.expectLastCall().times(1);
    EasyMock.replay(filterChain);

    Filter authenticatorFilter = AUTHENTICATOR.getFilter();
    authenticatorFilter.doFilter(req, resp, filterChain);

    EasyMock.verify(req, resp, filterChain);
  }

}
