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

package org.bremersee.adminserver.config;

import de.codecentric.boot.admin.server.config.AdminServerProperties;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.bremersee.actuator.security.authentication.ActuatorAuthProperties;
import org.bremersee.security.authentication.AuthProperties;
import org.bremersee.security.authentication.AuthProperties.PathMatcherProperties;
import org.bremersee.security.authentication.PasswordFlowAuthenticationManager;
import org.bremersee.security.core.AuthorityConstants;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/**
 * The security configuration.
 */
@Configuration
@EnableWebSecurity
@EnableConfigurationProperties({
    AdminServerProperties.class,
    AuthProperties.class,
    ActuatorAuthProperties.class
})
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

  private final AdminServerProperties adminServer;

  private final AuthProperties authProperties;

  private final ActuatorAuthProperties actuatorAuthProperties;

  private final PasswordFlowAuthenticationManager authenticationManager;

  public SecurityConfiguration(
      AdminServerProperties adminServer,
      AuthProperties authProperties,
      ActuatorAuthProperties actuatorAuthProperties,
      ObjectProvider<PasswordFlowAuthenticationManager> authenticationManagerProvider) {
    this.adminServer = adminServer;
    this.authProperties = authProperties;
    this.actuatorAuthProperties = actuatorAuthProperties;
    this.authenticationManager = authenticationManagerProvider.getIfAvailable();
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {

    SavedRequestAwareAuthenticationSuccessHandler successHandler
        = new SavedRequestAwareAuthenticationSuccessHandler();
    successHandler.setTargetUrlParameter("redirectTo");
    successHandler.setDefaultTargetUrl(this.adminServer.path("/"));

    List<String> roles = new ArrayList<>(authProperties.getRoleDefinitions().get("admin"));
    if (roles.isEmpty()) {
      roles.add(AuthorityConstants.ADMIN_ROLE_NAME);
    }
    PathMatcherProperties anyRequestMatcher = new PathMatcherProperties();
    anyRequestMatcher.setRoles(roles);

    if (authenticationManager != null) {
      http.authenticationProvider(authenticationManager);
    }

    http
        .authorizeRequests((authorizeRequests) -> authorizeRequests
            .antMatchers(adminServer.path("/assets/**")).permitAll()
            .antMatchers(adminServer.path("/login")).permitAll()
            .antMatchers(adminServer.path("/actuator/health")).permitAll()
            .antMatchers(adminServer.path("/actuator/info")).permitAll()
            .antMatchers(HttpMethod.OPTIONS, adminServer.path("/actuator/**")).permitAll()
            .antMatchers(HttpMethod.GET, adminServer.path("/actuator/**"))
            .access(actuatorAuthProperties.buildAccessExpression())
            .antMatchers(adminServer.path("/actuator/**"))
            .access(actuatorAuthProperties.buildAdminAccessExpression())
            .anyRequest()
            .access(anyRequestMatcher.accessExpression(authProperties::ensureRolePrefix)))
        .formLogin((formLogin) -> formLogin
            .loginPage(adminServer.path("/login")).successHandler(successHandler)
            .and())
        .logout((logout) -> logout.logoutUrl(adminServer.path("/logout")))
        .httpBasic(Customizer.withDefaults())
        .csrf((csrf) -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            .ignoringRequestMatchers(
                new AntPathRequestMatcher(adminServer.path("/instances"),
                    HttpMethod.POST.toString()),
                new AntPathRequestMatcher(adminServer.path("/instances/*"),
                    HttpMethod.DELETE.toString()),
                new AntPathRequestMatcher(adminServer.path("/actuator/**"))
            ))
        .rememberMe((rememberMe) -> rememberMe.key(UUID.randomUUID().toString())
            .tokenValiditySeconds(1209600));
  }

}
