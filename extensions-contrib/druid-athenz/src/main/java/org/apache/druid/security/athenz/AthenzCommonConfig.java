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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Objects;

public class AthenzCommonConfig
{
  private static final String DEFAULT_CONFIG_FILE = "/home/athenz/conf/athenz/athenz.conf";
  private static final String DEFAULT_POLICY_DIR = "/home/athenz/var/zpe";

  @JsonProperty
  private final String configFile;

  @JsonProperty
  private final String policyDir;

  @JsonProperty
  private final String domain;

  @JsonCreator
  public AthenzCommonConfig(
      @JsonProperty("configFile") String configFile,
      @JsonProperty("policyDir") String policyDir,
      @JsonProperty("domain") String domain
  )
  {
    this.configFile = configFile == null ? DEFAULT_CONFIG_FILE : configFile;
    this.policyDir = policyDir == null ? DEFAULT_POLICY_DIR : policyDir;
    this.domain = Objects.requireNonNull(domain);
  }

  @JsonProperty
  public String getConfigFile()
  {
    return configFile;
  }

  @JsonProperty
  public String getPolicyDir()
  {
    return policyDir;
  }

  @JsonProperty
  public String getDomain()
  {
    return domain;
  }
}
