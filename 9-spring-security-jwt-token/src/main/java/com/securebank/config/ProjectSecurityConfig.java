package com.securebank.config;

import com.securebank.filter.*;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Arrays;
import java.util.Collections;

@Configuration
public class ProjectSecurityConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

        /**
         * It ensures that the framework uses the specified attribute name to identify and extract the CSRF token from incoming requests.
         */
        CsrfTokenRequestAttributeHandler requestHandler = new CsrfTokenRequestAttributeHandler();
        requestHandler.setCsrfRequestAttributeName("_csrf");

        /**
         * SessionCreationPolicy.STATELESS: Sets the session creation policy to STATELESS. In a stateless session, the server does not create or use an HttpSession. Each request is treated independently,
         * and the client is responsible for including any necessary authentication information (e.g., tokens) in each request.
         */
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                .cors(corsCustomizer -> corsCustomizer.configurationSource(new CorsConfigurationSource() {
                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                        CorsConfiguration config = new CorsConfiguration();
                        config.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
                        config.setAllowedMethods(Collections.singletonList("*"));
                        config.setAllowCredentials(true);
                        config.setAllowedHeaders(Collections.singletonList("*"));
                        /**
                         *  The config is setting the list of headers that are exposed to the browser during a cross-origin request.
                         */
                        config.setExposedHeaders(Arrays.asList("Authorization"));
                        config.setMaxAge(3600L);  //by seconds
                        return config;
                    }
                    // Ignoring CSRF protection for public APIs
                })).csrf((csrf) -> csrf.csrfTokenRequestHandler(requestHandler).ignoringRequestMatchers("/contact", "/register")
                        //this configuration is telling Spring Security to use a CSRF token repository based on cookies (CookieCsrfTokenRepository) and allows
                        // the cookie to be accessed by JavaScript (withHttpOnlyFalse()).
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
                // Filter to ensuring that the CSRF token is included in the response headers by this class CsrfCookieFilter.
                .addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class)

                // Adding custom filter Before BasicAuthenticationFilter using addFilterBefore() method
                .addFilterBefore(new RequestValidationBeforeFilter(), BasicAuthenticationFilter.class)

                // Adding custom filter At BasicAuthenticationFilter using addFilterAt() method
                .addFilterAt(new AuthoritiesLoggingAtFilter(), BasicAuthenticationFilter.class)

                // Adding custom filter After BasicAuthenticationFilter using addFilterAfter() method
                .addFilterAfter(new AuthoritiesLoggingAfterFilter(), BasicAuthenticationFilter.class)

                // Generate JWT Tokens
                .addFilterAfter(new JWTTokenGeneratorFilter(), BasicAuthenticationFilter.class)
                // Validate JWT Tokens
                .addFilterBefore(new JWTTokenValidatorFilter(), BasicAuthenticationFilter.class)

                .authorizeHttpRequests((requests) -> requests
                        /** Access restricted based on user Role. */.requestMatchers("/myAccount").hasRole("USER").requestMatchers("/myBalance").hasAnyRole("USER", "ADMIN").requestMatchers("/myLoans").hasRole("USER").requestMatchers("/myCards").hasRole("USER").requestMatchers("/user").authenticated()
                        // Any authenticated user has access to those pages.
                        /* .requestMatchers("/myAccount", "/myBalance", "/myCards", "/myLoans", "/user")
                         .authenticated()*/
                        // Service without any Security
                        .requestMatchers("/notices", "/contact", "/register").permitAll()).formLogin(Customizer.withDefaults()).httpBasic(Customizer.withDefaults());

        return http.build();
    }

    /**
     * BCryptPasswordEncoder instead of NoOpPasswordEncoder
     *
     * @return
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


}
