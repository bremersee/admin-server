package org.bremersee.adminserver.config;

import de.codecentric.boot.admin.server.config.AdminServerProperties;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.bremersee.security.authentication.AuthenticationProperties;
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

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

  /*
  @ConditionalOnProperty(
      prefix = "bremersee.security.authentication",
      name = "enable-jwt-support",
      havingValue = "true")
  @Configuration
  @Slf4j
  @EnableConfigurationProperties(AuthenticationProperties.class)
  static class PasswordFlowAuthentication extends WebSecurityConfigurerAdapter {

  }
  */

  @ConditionalOnProperty(
      prefix = "bremersee.security.authentication",
      name = "enable-jwt-support",
      havingValue = "false", matchIfMissing = true)
  @Configuration
  @Slf4j
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

    @Override
    protected void configure(HttpSecurity http) throws Exception {
      SavedRequestAwareAuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
      successHandler.setTargetUrlParameter("redirectTo");
      successHandler.setDefaultTargetUrl(this.adminServer.path("/"));

      http
          .authorizeRequests((authorizeRequests) -> authorizeRequests
              .antMatchers(this.adminServer.path("/assets/**")).permitAll()
              .antMatchers(this.adminServer.path("/login")).permitAll()
              .antMatchers(adminServer.path("/actuator/health")).permitAll()
              .antMatchers(adminServer.path("/actuator/info")).permitAll()
              .antMatchers(adminServer.path("/actuator/**")).access(properties.getActuator().buildAccessExpression())
              .anyRequest().authenticated())
          .formLogin((formLogin) -> formLogin
              .loginPage(this.adminServer.path("/login")).successHandler(successHandler)
              .and())
          .logout((logout) -> logout.logoutUrl(this.adminServer.path("/logout")))
          .httpBasic(Customizer.withDefaults())
          .csrf((csrf) -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
              .ignoringRequestMatchers(
                  new AntPathRequestMatcher(this.adminServer.path("/instances"),
                      HttpMethod.POST.toString()),
                  new AntPathRequestMatcher(this.adminServer.path("/instances/*"),
                      HttpMethod.DELETE.toString()),
                  new AntPathRequestMatcher(this.adminServer.path("/actuator/**"))
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

}
