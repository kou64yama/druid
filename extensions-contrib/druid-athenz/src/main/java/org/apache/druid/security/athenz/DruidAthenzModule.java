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

import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.google.common.collect.ImmutableList;
import com.google.inject.Binder;
import com.google.inject.Injector;
import com.google.inject.Provides;
import com.yahoo.athenz.common.config.AthenzConfig;
import com.yahoo.athenz.zpe.ZpeClient;
import com.yahoo.athenz.zpe.ZpeUpdater;
import com.yahoo.athenz.zpe.pkey.PublicKeyStore;
import com.yahoo.athenz.zpe.pkey.file.FilePublicKeyStore;
import com.yahoo.rdl.JSON;
import org.apache.druid.guice.JsonConfigProvider;
import org.apache.druid.guice.LazySingleton;
import org.apache.druid.initialization.DruidModule;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

public class DruidAthenzModule implements DruidModule
{
  @Override
  public List<? extends Module> getJacksonModules()
  {
    return ImmutableList.of(
        new SimpleModule("DruidAthenz").registerSubtypes(
            AthenzAuthenticator.class,
            AthenzEscalator.class,
            AthenzAuthorizer.class
        )
    );
  }

  @Override
  public void configure(Binder binder)
  {
    JsonConfigProvider.bind(binder, "druid.auth.athenz.common", AthenzCommonConfig.class);
  }

  @Provides
  @LazySingleton
  public static AthenzConfig getAthenzConfig(Injector injector) throws IOException
  {
    AthenzCommonConfig common = injector.getInstance(AthenzCommonConfig.class);

    Path path = Paths.get(common.getConfigFile());
    byte[] bytes = Files.readAllBytes(path);
    return JSON.fromBytes(bytes, AthenzConfig.class);
  }

  @Provides
  @LazySingleton
  public static synchronized PublicKeyStore getPublicKeyStore(Injector injector)
  {
    AthenzCommonConfig common = injector.getInstance(AthenzCommonConfig.class);
    System.setProperty("athenz.athenz_conf", common.getConfigFile());

    FilePublicKeyStore keyStore = new FilePublicKeyStore();
    keyStore.init();
    return keyStore;
  }

  @Provides
  @LazySingleton
  public static synchronized ZpeClient getZpeClient(Injector injector)
  {
    AthenzCommonConfig common = injector.getInstance(AthenzCommonConfig.class);
    System.setProperty("athenz.zpe.policy_dir", common.getPolicyDir());

    ZpeUpdater updater = new ZpeUpdater();
    updater.init(common.getDomain());
    return updater;
  }
}
