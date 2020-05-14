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

import de.codecentric.boot.admin.server.config.EnableAdminServer;
import org.bremersee.actuator.security.authentication.ActuatorSecurityAutoConfiguration;
import org.bremersee.actuator.security.authentication.ResourceServerWithActuatorAutoConfiguration;
import org.bremersee.context.MessageSourceAutoConfiguration;
import org.bremersee.converter.ModelMapperAutoConfiguration;
import org.bremersee.exception.RestApiExceptionMapperAutoConfiguration;
import org.bremersee.exception.RestApiExceptionParserAutoConfiguration;
import org.bremersee.security.authentication.ResourceServerAutoConfiguration;
import org.bremersee.web.servlet.ApiExceptionResolverAutoConfiguration;
import org.bremersee.web.servlet.BaseCommonConvertersAutoConfiguration;
import org.bremersee.web.servlet.CorsAutoConfiguration;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * The application.
 *
 * @author Christian Bremer
 */
@SpringBootApplication(exclude = {
    ActuatorSecurityAutoConfiguration.class,
    ResourceServerAutoConfiguration.class,
    ResourceServerWithActuatorAutoConfiguration.class,
    CorsAutoConfiguration.class,
    ModelMapperAutoConfiguration.class,
    MessageSourceAutoConfiguration.class,
    RestApiExceptionMapperAutoConfiguration.class,
    RestApiExceptionParserAutoConfiguration.class,
    ApiExceptionResolverAutoConfiguration.class,
    BaseCommonConvertersAutoConfiguration.class
})
@EnableAdminServer
public class Application {

  /**
   * The entry point of application.
   *
   * @param args the input arguments
   */
  public static void main(String[] args) {
    SpringApplication.run(Application.class, args);
  }

}
