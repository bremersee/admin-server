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

import static org.springframework.util.ObjectUtils.isEmpty;

import de.codecentric.boot.admin.server.config.AdminServerProperties;
import org.bremersee.spring.boot.autoconfigure.security.authentication.AuthenticationProperties;
import org.bremersee.spring.security.ldaptive.authentication.LdaptiveRememberMeServices;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer.FrameOptionsConfig;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

/**
 * The web security configuration.
 *
 * @author Christian Bremer
 */
@EnableWebSecurity
@EnableConfigurationProperties({
    AdminServerProperties.class, AuthenticationProperties.class, WebSecurityProperties.class
})
@Configuration
class WebSecurityConfiguration {

  private static final String ACTUATOR_PATH = "/actuator";

  private static final String ALL_PATH = "/**";

  private final AdminServerProperties adminServer;

  private final AuthenticationProperties authenticationProperties;

  private final WebSecurityProperties securityProperties;

  private final LdaptiveRememberMeServices rememberMeServices;

  /**
   * Instantiates a new web security configuration.
   *
   * @param adminServerProperties the admin server properties
   * @param authenticationProperties the authentication properties
   * @param securityProperties the security properties
   * @param rememberMeServices the remember me services
   */
  WebSecurityConfiguration(
      AdminServerProperties adminServerProperties,
      AuthenticationProperties authenticationProperties,
      WebSecurityProperties securityProperties,
      ObjectProvider<LdaptiveRememberMeServices> rememberMeServices) {
    this.adminServer = adminServerProperties;
    this.authenticationProperties = authenticationProperties;
    this.securityProperties = securityProperties;
    this.rememberMeServices = rememberMeServices.getIfAvailable();
  }

  private String getActuatorPath(String endpointPath) {
    return adminServer.path(ACTUATOR_PATH + endpointPath);
  }

  private AuthenticationSuccessHandler getAuthenticationSuccessHandler() {
    SavedRequestAwareAuthenticationSuccessHandler successHandler
        = new SavedRequestAwareAuthenticationSuccessHandler();
    successHandler.setTargetUrlParameter("redirectTo");
    successHandler.setDefaultTargetUrl(this.adminServer.path("/"));
    return successHandler;
  }

  /**
   * Creates security filter chain.
   *
   * @param http the http
   * @return the security filter chain
   */
  @Bean
  SecurityFilterChain filterChain(HttpSecurity http) {
    String[] actuatorReadRoles = authenticationProperties.getActuator().getReadRoles()
        .toArray(new String[0]);
    String[] actuatorWriteRoles = authenticationProperties.getActuator().getWriteRoles()
        .toArray(new String[0]);

    http
        .authorizeHttpRequests(customizer -> customizer
            .requestMatchers(HttpMethod.OPTIONS, ALL_PATH)
            .permitAll()

            .requestMatchers(PathPatternRequestMatcher.withDefaults()
                .matcher(getActuatorPath("/info")))
            .permitAll()
            .requestMatchers(PathPatternRequestMatcher.withDefaults()
                .matcher(getActuatorPath("/health")))
            .permitAll()
            .requestMatchers(PathPatternRequestMatcher.withDefaults()
                .matcher(HttpMethod.GET, getActuatorPath(ALL_PATH)))
            .hasAnyAuthority(actuatorReadRoles)
            .requestMatchers(PathPatternRequestMatcher.withDefaults()
                .matcher(getActuatorPath(ALL_PATH)))
            .hasAnyAuthority(actuatorWriteRoles)

            // Permit access to static resources
            .requestMatchers(PathPatternRequestMatcher.withDefaults()
                .matcher(adminServer.path("/assets/**")))
            .permitAll()
            // Permit access to login page
            .requestMatchers(PathPatternRequestMatcher.withDefaults()
                .matcher(adminServer.path("/login")))
            .permitAll()

            .anyRequest()
            .hasAuthority(securityProperties.getAdminServerAccessRole()))

        .formLogin(form -> form
            .loginPage(adminServer.path("/login"))
            .successHandler(getAuthenticationSuccessHandler()))

        .logout(logout -> logout.logoutSuccessUrl("/index"))

        .httpBasic(customizer -> customizer.realmName("Admin Server"))

        .addFilterAfter(new CustomCsrfFilter(), BasicAuthenticationFilter.class)

        .headers(configurer -> configurer
            .frameOptions(FrameOptionsConfig::sameOrigin))

        .csrf(customizer -> customizer
            .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
            .ignoringRequestMatchers(
                // Exempt client registration endpoints
                PathPatternRequestMatcher.withDefaults()
                    .matcher(HttpMethod.POST, adminServer.path("/instances")),
                PathPatternRequestMatcher.withDefaults()
                    .matcher(HttpMethod.DELETE, adminServer.path("/instances/*")),
                // Exempt Admin Server's own actuator
                PathPatternRequestMatcher.withDefaults()
                    .matcher(getActuatorPath(ALL_PATH)))
        );

    if (!isEmpty(rememberMeServices)) {
      http.rememberMe(customizer -> customizer
          .userDetailsService(rememberMeServices.getUserDetailsService())
          .rememberMeServices(rememberMeServices));
    }

    return http.build();
  }

}
