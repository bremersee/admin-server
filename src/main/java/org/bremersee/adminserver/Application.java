package org.bremersee.adminserver;

import de.codecentric.boot.admin.server.config.EnableAdminServer;
import org.bremersee.context.MessageSourceAutoConfiguration;
import org.bremersee.converter.ModelMapperAutoConfiguration;
import org.bremersee.exception.RestApiExceptionMapperAutoConfiguration;
import org.bremersee.exception.RestApiExceptionParserAutoConfiguration;
import org.bremersee.web.servlet.ApiExceptionResolverAutoConfiguration;
import org.bremersee.web.servlet.BaseCommonConvertersAutoConfiguration;
import org.bremersee.web.servlet.CorsAutoConfiguration;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(exclude = {
		ModelMapperAutoConfiguration.class,
		MessageSourceAutoConfiguration.class,
		RestApiExceptionMapperAutoConfiguration.class,
		RestApiExceptionParserAutoConfiguration.class,
		ApiExceptionResolverAutoConfiguration.class,
		BaseCommonConvertersAutoConfiguration.class,
		CorsAutoConfiguration.class
})
@EnableAdminServer
public class Application {

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}

}
