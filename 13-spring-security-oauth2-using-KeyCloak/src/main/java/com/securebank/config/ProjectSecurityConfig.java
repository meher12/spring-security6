package com.securebank.config;

import com.securebank.filter.CsrfCookieFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
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
         * This code is configuring the JwtAuthenticationConverter to use a custom converter that knows how to extract roles from a Keycloak JWT.
         * This is necessary because Keycloak stores roles in a different format than the standard JWT format.
         */
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new KeycloakRoleConverter());

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


                .authorizeHttpRequests((requests) -> requests
                        /** Access restricted based on user Role. */
                        .requestMatchers("/myAccount").hasRole("USER")
                        .requestMatchers("/myBalance").hasAnyRole("USER", "ADMIN")
                        .requestMatchers("/myLoans").authenticated()
                        .requestMatchers("/myCards").hasRole("USER")
                        .requestMatchers("/user").authenticated()
                        // Any authenticated user has access to those pages.
                        /* .requestMatchers("/myAccount", "/myBalance", "/myCards", "/myLoans", "/user")
                         .authenticated()*/
                        // Service without any Security
                        .requestMatchers("/notices", "/contact", "/register").permitAll())
                        .oauth2ResourceServer(oauth2ResourceServerCustomizer ->
                         oauth2ResourceServerCustomizer.jwt(jwtCustomizer -> jwtCustomizer.jwtAuthenticationConverter(jwtAuthenticationConverter)));


        return http.build();
    }


}
