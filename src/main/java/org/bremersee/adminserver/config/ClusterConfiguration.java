/*
 * Copyright 2026 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bremersee.adminserver.config;

import static de.codecentric.boot.admin.server.config.AdminServerHazelcastAutoConfiguration.DEFAULT_NAME_EVENT_STORE_MAP;
import static de.codecentric.boot.admin.server.config.AdminServerHazelcastAutoConfiguration.DEFAULT_NAME_SENT_NOTIFICATIONS_MAP;

import com.hazelcast.config.Config;
import com.hazelcast.config.EvictionConfig;
import com.hazelcast.config.EvictionPolicy;
import com.hazelcast.config.InMemoryFormat;
import com.hazelcast.config.JoinConfig;
import com.hazelcast.config.MapConfig;
import com.hazelcast.config.MaxSizePolicy;
import com.hazelcast.config.MergePolicyConfig;
import com.hazelcast.config.NetworkConfig;
import com.hazelcast.spi.merge.PutIfAbsentMergePolicy;
import de.codecentric.boot.admin.server.domain.entities.InstanceRepository;
import de.codecentric.boot.admin.server.notify.Notifier;
import de.codecentric.boot.admin.server.notify.filter.FilteringNotifier;
import de.codecentric.boot.admin.server.notify.filter.NotificationFilter;
import java.util.concurrent.ConcurrentMap;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.boot.autoconfigure.jmx.JmxAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

/**
 * The cluster configuration (see <a
 * href="https://docs.spring-boot-admin.com/4.1.2/docs/server/Clustering">Clustering</a>).
 *
 * @author docs.spring-boot-admin.com
 */
@ConditionalOnBooleanProperty(prefix = "spring.boot.admin.hazelcast", name = "enabled")
@Configuration
class ClusterConfiguration {

  JmxAutoConfiguration n;

  /**
   * Instantiates a new cluster configuration.
   */
  ClusterConfiguration() {
    super();
  }

  /**
   * Creates hazelcast config.
   *
   * @return the config
   */
  @Bean
  Config hazelcastConfig() {
    // This map is used to store the events.
    // It should be configured to reliably hold all the data,
    // Spring Boot Admin will compact the events, if there are too many
    MapConfig eventStoreMap = new MapConfig(DEFAULT_NAME_EVENT_STORE_MAP)
        .setInMemoryFormat(InMemoryFormat.OBJECT)
        .setBackupCount(1)
        .setMergePolicyConfig(new MergePolicyConfig(PutIfAbsentMergePolicy.class.getName(), 100));
    // This map is used to deduplicate the notifications.
    // If data in this map gets lost it should not be a big issue as it will atmost
    // lead to
    // the same notification to be sent by multiple instances
    MapConfig sentNotificationsMap = new MapConfig(DEFAULT_NAME_SENT_NOTIFICATIONS_MAP)
        .setInMemoryFormat(InMemoryFormat.OBJECT)
        .setBackupCount(1)
        .setEvictionConfig(new EvictionConfig().setEvictionPolicy(EvictionPolicy.LRU)
            .setMaxSizePolicy(MaxSizePolicy.PER_NODE))
        .setMergePolicyConfig(new MergePolicyConfig(PutIfAbsentMergePolicy.class.getName(), 100));

    // This map is used to share notification filter rules across all cluster nodes.
    // Filters added on one node will automatically be visible to all other nodes.
    // Coming with 4.1.5
    /*
   MapConfig notificationFiltersMap = new MapConfig(DEFAULT_NAME_NOTIFICATION_FILTERS_MAP)
        .setInMemoryFormat(InMemoryFormat.OBJECT)
        .setBackupCount(1)
        .setMergePolicyConfig(new MergePolicyConfig(PutIfAbsentMergePolicy.class.getName(), 100));
   */

    Config config = new Config();
    config.addMapConfig(eventStoreMap);
    config.addMapConfig(sentNotificationsMap);
    //config.addMapConfig(notificationFiltersMap);
    config.setProperty("hazelcast.jmx", "true");

    // network and join configuration (simple defaults good for local/dev)
    NetworkConfig network = config.getNetworkConfig();
    network
        .setPort(5701)
        .setPortAutoIncrement(true)
        .setPortCount(98);

    JoinConfig join = network.getJoin();
    join.getMulticastConfig().setEnabled(true);

    return config;
  }

  // Coming with 4.1.5
  /*
  @Bean
  @Primary
  public FilteringNotifier filteringNotifier(
      @Qualifier("mailNotifier") Notifier delegate,
      InstanceRepository repository,
      @Qualifier("notificationFiltersMap") ConcurrentMap<String, NotificationFilter> filters) {
    FilteringNotifier fn = new FilteringNotifier(delegate, repository);

    return fn;
  }
  */

}
