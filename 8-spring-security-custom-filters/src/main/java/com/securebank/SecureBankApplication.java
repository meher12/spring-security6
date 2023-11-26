package com.securebank;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

/** **** Optional ****
 * @ComponentScan({"com.securebank.controller", "com.securebank.config"})
 * @EnableJpaRepositories("com.securebank.repository")
 * @EntityScan("com.securebank.model")
 * @EnableWebSecurity
 */
@SpringBootApplication
@EnableWebSecurity(debug = true)
public class SecureBankApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecureBankApplication.class, args);
	}

}
