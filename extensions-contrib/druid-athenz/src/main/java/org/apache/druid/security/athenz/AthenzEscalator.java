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
import com.yahoo.athenz.auth.ServiceIdentityProvider;
import com.yahoo.athenz.auth.impl.SimpleServiceIdentityProvider;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.common.config.AthenzConfig;
import com.yahoo.athenz.zts.RoleToken;
import com.yahoo.athenz.zts.ZTSClient;
import org.apache.commons.codec.binary.Base64InputStream;
import org.apache.druid.java.util.common.logger.Logger;
import org.apache.druid.java.util.http.client.CredentialedHttpClient;
import org.apache.druid.java.util.http.client.HttpClient;
import org.apache.druid.java.util.http.client.Request;
import org.apache.druid.java.util.http.client.auth.Credentials;
import org.apache.druid.server.security.AuthenticationResult;
import org.apache.druid.server.security.Escalator;

import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@JsonTypeName("athenz")
public class AthenzEscalator implements Escalator, AutoCloseable
{
  private static final Logger log = new Logger(AthenzEscalator.class);

  private final ZTSClient ztsClient;
  private final String authorizerName;
  private final String name;
  private final String domain;
  private final String provider;
  private final String role;

  @JsonCreator
  public AthenzEscalator(
      @JacksonInject AthenzConfig config,
      @JsonProperty("authorizerName") String authorizerName,
      @JsonProperty("name") String name,
      @JsonProperty("domain") String domain,
      @JsonProperty("privateKey") String privateKey,
      @JsonProperty("keyId") String keyId,
      @JsonProperty("provider") String provider,
      @JsonProperty("role") String role
  )
  {
    this.authorizerName = authorizerName;
    this.name = name;
    this.domain = domain;
    this.provider = provider;
    this.role = role;

    ByteArrayInputStream inputStream = new ByteArrayInputStream(privateKey.getBytes(StandardCharsets.UTF_8));
    Base64InputStream base64 = new Base64InputStream(inputStream);
    InputStreamReader reader = new InputStreamReader(base64, StandardCharsets.UTF_8);
    PrivateKey key = Crypto.loadPrivateKey(reader);

    ServiceIdentityProvider siaProvider = new SimpleServiceIdentityProvider(domain, name, key, keyId);
    ztsClient = new ZTSClient(config.getZtsUrl(), domain, name, siaProvider);
  }

  @Override
  public HttpClient createEscalatedClient(HttpClient baseClient)
  {
    return new CredentialedHttpClient(new AthenzRoleAuthCredentials(), baseClient);
  }

  @Override
  public AuthenticationResult createEscalatedAuthenticationResult()
  {
    Map<String, Object> context = new HashMap<>();
    context.put("domain", provider);
    context.put("roles", Collections.singletonList(role));
    return new AuthenticationResult(domain + "." + name, authorizerName, null, context);
  }

  @Override
  public void close()
  {
    ztsClient.close();
  }

  private class AthenzRoleAuthCredentials implements Credentials
  {

    @Override
    public Request addCredentials(Request builder)
    {
      RoleToken roleToken = ztsClient.getRoleToken(provider, role);
      log.debug("Athenz-Role-Auth: %s", roleToken.getToken());
      return builder.setHeader("Athenz-Role-Auth", roleToken.getToken());
    }
  }
}
