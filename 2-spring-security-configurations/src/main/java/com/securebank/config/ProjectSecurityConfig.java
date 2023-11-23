package com.securebank.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class ProjectSecurityConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests()
                // Service with Security
                .requestMatchers("/myAccount", "/myBalance", "/myCards", "/myLoans")
                .authenticated()
                // Service without any Security
                .requestMatchers("/notices", "/contact").permitAll();

        // Denying all the requests
       /* http.authorizeHttpRequests()
                        .anyRequest().denyAll();*/
        // Permit All the request
        /* http.authorizeHttpRequests()
                        .anyRequest().permitAll(); */
        http.formLogin(Customizer.withDefaults());
        http.httpBasic(Customizer.withDefaults());
        return (SecurityFilterChain) http.build();
    }
}
