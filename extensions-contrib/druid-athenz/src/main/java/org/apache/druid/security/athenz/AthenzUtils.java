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
import org.apache.druid.server.security.AuthenticationResult;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class AthenzUtils
{

  public static Map<String, Object> getContext(RoleToken token)
  {
    Map<String, Object> context = new HashMap<>(2);
    context.put("domain", token.getDomain());
    context.put("roles", Collections.unmodifiableList(token.getRoles()));
    return Collections.unmodifiableMap(context);
  }

  public static String getDomain(AuthenticationResult authenticationResult)
  {
    Map<String, Object> context = authenticationResult.getContext();
    if (context == null) {
      return "";
    }

    return (String) context.getOrDefault("domain", "");
  }

  @SuppressWarnings("unchecked")
  public static List<String> getRoles(AuthenticationResult authenticationResult)
  {
    Map<String, Object> context = authenticationResult.getContext();
    if (context == null) {
      return Collections.emptyList();
    }

    return (List<String>) context.getOrDefault("roles", Collections.emptyList());
  }

}
