---
layout: doc_page
title: "Athenz"
---

<!--
  ~ Licensed to the Apache Software Foundation (ASF) under one
  ~ or more contributor license agreements.  See the NOTICE file
  ~ distributed with this work for additional information
  ~ regarding copyright ownership.  The ASF licenses this file
  ~ to you under the Apache License, Version 2.0 (the
  ~ "License"); you may not use this file except in compliance
  ~ with the License.  You may obtain a copy of the License at
  ~
  ~   http://www.apache.org/licenses/LICENSE-2.0
  ~
  ~ Unless required by applicable law or agreed to in writing,
  ~ software distributed under the License is distributed on an
  ~ "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  ~ KIND, either express or implied.  See the License for the
  ~ specific language governing permissions and limitations
  ~ under the License.
  -->

# Athenz

## Usage

**athenz.yml**:

```yaml
domain:
  name: my.druid
  audit_enabled: false
  roles:
    - name: admin
      members:
        - users.you
    - name: druid
      members:
        - my.druid.historical
        - my.druid.broker
        - my.druid.coordinator
        - my.druid.overlord
        - my.druid.middle-manager
  policies:
    - name: admin
      assertions:
        - grant * to admin on *
    - name: druid
      assertions:
        - grant * to druid on datasource-*
        - grant * to druid on config-*
        - grant * to druid on state-*
    - name: user
      assertions:
        - grant read to user on datasource-*
```

```shell
$ openssl genrsa -out historical.pem
$ openssl genrsa -out broker.pem
$ openssl genrsa -out coordinator.pem
$ openssl genrsa -out overlord.pem
$ openssl genrsa -out middle-manager.pem
```

```shell
$ zms-cli -z https://<zms-server>/zms/v1 import-domain 
$ zms-cli -z https://<zms-server>/zms/v1 -d my.druid add-service
```

```
druid.auth.athenz.common.configFile=/home/athenz/conf/athenz/athenz.conf
druid.auth.athenz.common.policyDir=/home/athenz/var/zpe
```

```
druid.auth.authenticatorChain=["MyAthenzAuthenticator"]

druid.auth.authenticator.MyAthenzAuthenticator.type=athenz
```
