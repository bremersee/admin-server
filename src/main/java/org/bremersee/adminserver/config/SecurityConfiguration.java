package org.bremersee.adminserver.config;

import de.codecentric.boot.admin.server.config.AdminServerProperties;
import java.util.UUID;
import org.bremersee.security.authentication.AuthenticationProperties;
import org.bremersee.security.authentication.PasswordFlowAuthenticationManager;
import org.bremersee.security.core.AuthorityConstants;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

  @ConditionalOnProperty(
      prefix = "bremersee.security.authentication",
      name = "enable-jwt-support",
      havingValue = "false", matchIfMissing = true)
  @Configuration
  @EnableConfigurationProperties(AuthenticationProperties.class)
  static class SimpleUserAuthentication extends WebSecurityConfigurerAdapter {

    private AdminServerProperties adminServer;

    private AuthenticationProperties properties;

    public SimpleUserAuthentication(
        AdminServerProperties adminServer,
        AuthenticationProperties properties) {
      this.adminServer = adminServer;
      this.properties = properties;
    }

    @SuppressWarnings("DuplicatedCode")
    @Override
    protected void configure(HttpSecurity http) throws Exception {
      SavedRequestAwareAuthenticationSuccessHandler successHandler
          = new SavedRequestAwareAuthenticationSuccessHandler();
      successHandler.setTargetUrlParameter("redirectTo");
      successHandler.setDefaultTargetUrl(this.adminServer.path("/"));

      http
          .authorizeRequests((authorizeRequests) -> authorizeRequests
              .antMatchers(adminServer.path("/assets/**")).permitAll()
              .antMatchers(adminServer.path("/login")).permitAll()
              .antMatchers(adminServer.path("/actuator/health")).permitAll()
              .antMatchers(adminServer.path("/actuator/info")).permitAll()
              .antMatchers(HttpMethod.OPTIONS, adminServer.path("/actuator/**")).permitAll()
              .antMatchers(HttpMethod.GET, adminServer.path("/actuator/**"))
              .access(properties.getActuator()
                  .buildAccessExpression(properties::ensureRolePrefix))
              .antMatchers(adminServer.path("/actuator/**"))
              .access(properties.getActuator()
                  .buildAdminAccessExpression(properties::ensureRolePrefix))
              .anyRequest()
              .access(properties.getApplication().buildAccessExpression(
                  false, false, false, true,
                  properties::ensureRolePrefix,
                  AuthorityConstants.ADMIN_ROLE_NAME)))
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

    @Bean
    @Override
    public UserDetailsService userDetailsService() {
      return new InMemoryUserDetailsManager(properties.buildBasicAuthUserDetails());
    }

  }

  @ConditionalOnProperty(
      prefix = "bremersee.security.authentication",
      name = "enable-jwt-support",
      havingValue = "true")
  @Configuration
  @EnableConfigurationProperties(AuthenticationProperties.class)
  static class PasswordFlowAuthentication extends WebSecurityConfigurerAdapter {

    private AdminServerProperties adminServer;

    private AuthenticationProperties properties;

    private PasswordFlowAuthenticationManager passwordFlowAuthenticationManager;

    public PasswordFlowAuthentication(
        AdminServerProperties adminServer,
        AuthenticationProperties properties,
        ObjectProvider<PasswordFlowAuthenticationManager> passwordFlowAuthenticationManager) {
      this.adminServer = adminServer;
      this.properties = properties;
      this.passwordFlowAuthenticationManager = passwordFlowAuthenticationManager.getIfAvailable();
      Assert.notNull(
          this.passwordFlowAuthenticationManager,
          "Password flow authentication manager must be present.");
    }

    @SuppressWarnings("DuplicatedCode")
    @Override
    protected void configure(HttpSecurity http) throws Exception {
      SavedRequestAwareAuthenticationSuccessHandler successHandler
          = new SavedRequestAwareAuthenticationSuccessHandler();
      successHandler.setTargetUrlParameter("redirectTo");
      successHandler.setDefaultTargetUrl(adminServer.path("/"));

      http
          .authorizeRequests((authorizeRequests) -> authorizeRequests
              .antMatchers(adminServer.path("/assets/**")).permitAll()
              .antMatchers(adminServer.path("/login")).permitAll()
              .antMatchers(adminServer.path("/actuator/health")).permitAll()
              .antMatchers(adminServer.path("/actuator/info")).permitAll()
              .antMatchers(HttpMethod.OPTIONS, adminServer.path("/actuator/**")).permitAll()
              .antMatchers(HttpMethod.GET, adminServer.path("/actuator/**"))
              .access(properties.getActuator()
                  .buildAccessExpression(properties::ensureRolePrefix))
              .antMatchers(adminServer.path("/actuator/**"))
              .access(properties.getActuator()
                  .buildAdminAccessExpression(properties::ensureRolePrefix))
              .anyRequest()
              .access(properties.getApplication().buildAccessExpression(
                  false, false, false, true,
                  properties::ensureRolePrefix,
                  AuthorityConstants.ADMIN_ROLE_NAME)))
          .authenticationProvider(passwordFlowAuthenticationManager)
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

}
