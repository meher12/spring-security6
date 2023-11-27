package com.securebank;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

/**
 * *** Optional ****
 *
 * @ComponentScan({"com.securebank.controller", "com.securebank.config"})
 * @EnableJpaRepositories("com.securebank.repository")
 * @EntityScan("com.securebank.model")
 * @EnableWebSecurity
 */
@SpringBootApplication
@Configuration
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class SecureBankApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecureBankApplication.class, args);
    }

}
