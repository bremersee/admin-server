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

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.restclient.RestTemplateBuilder;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;

/**
 * The application tests.
 *
 * @author Christian Bremer
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles({"test"})
class ApplicationTests {

  private static final String USER = "admin";

  private static final String USER_PASS = "changeit";

  /**
   * The rest template builder.
   */
  @Autowired
  RestTemplateBuilder restTemplateBuilder;

  /**
   * The local server port.
   */
  @LocalServerPort
  int port;

  /**
   * Base url of the local server.
   *
   * @return the base url of the local server
   */
  String baseUrl() {
    return "http://localhost:" + port;
  }

  /**
   * Fetch health.
   */
  @Test
  void fetchHealth() {
    ResponseEntity<String> response = restTemplateBuilder
        .baseUri(baseUrl())
        .build()
        .getForEntity("/actuator/health", String.class);
    assertThat(response.getStatusCode())
        .isEqualTo(HttpStatus.OK);
  }

  /**
   * Fetch info.
   */
  @Test
  void fetchInfo() {
    ResponseEntity<String> response = restTemplateBuilder
        .baseUri(baseUrl())
        .build()
        .getForEntity("/actuator/info", String.class);
    assertThat(response.getStatusCode())
        .isEqualTo(HttpStatus.OK);
  }

  /**
   * Fetch beans.
   */
  @Test
  void fetchBeans() {
    ResponseEntity<String> response = restTemplateBuilder
        .basicAuthentication(USER, USER_PASS)
        .baseUri(baseUrl())
        .build()
        .getForEntity("/actuator/beans", String.class);
    assertThat(response.getStatusCode())
        .isEqualTo(HttpStatus.OK);
  }

}
