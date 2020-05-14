/*
 * Copyright 2020 the original author or authors.
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

package org.bremersee.adminserver;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;

/**
 * The application tests.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles({"in-memory"})
class ApplicationTests {

  private static final String actuatorUser = "actuator";

  private static final String actuatorPass = "actuator";

  /**
   * The rest template.
   */
  @Autowired
  TestRestTemplate restTemplate;

  /**
   * Fetch health.
   */
  @Test
  void fetchHealth() {
    ResponseEntity<String> response = restTemplate
        .getForEntity("/actuator/health", String.class);
    assertEquals(HttpStatus.OK, response.getStatusCode());
  }

  /**
   * Fetch info.
   */
  @Test
  void fetchInfo() {
    ResponseEntity<String> response = restTemplate
        .getForEntity("/actuator/info", String.class);
    assertEquals(HttpStatus.OK, response.getStatusCode());
  }

  /**
   * Fetch metrics.
   */
  @Test
  void fetchMetrics() {
    ResponseEntity<String> response = restTemplate
        .withBasicAuth(actuatorUser, actuatorPass)
        .getForEntity("/actuator/metrics", String.class);
    assertEquals(HttpStatus.OK, response.getStatusCode());
  }

  /**
   * Fetch metrics and expect status 302 (because form login is enabled).
   */
  @Test
  void fetchMetricsAndExpect302() {
    ResponseEntity<String> response = restTemplate
        .getForEntity("/actuator/metrics", String.class);
    assertEquals(HttpStatus.FOUND, response.getStatusCode());
  }

}
