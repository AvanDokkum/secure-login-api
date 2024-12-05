package com.webcanis.client_application;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
//@EnableWebSecurity
public class SecurityConfig {

    /*
        1. Disable Form Login: By not configuring form-based login (formLogin()), you prevent the application from redirecting unauthenticated requests to a login page.
        2. Permit All Requests: The authorizeHttpRequests().anyRequest().permitAll() configuration allows all requests without authentication, suitable for a client application acting on its own behalf.
        3. Disable CSRF Protection: Disabling CSRF protection is appropriate for non-browser clients, as they are not vulnerable to CSRF attacks.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/").permitAll() // Allow homepage
                        .anyRequest().authenticated()    // Secure other requests
                )
                .formLogin(Customizer.withDefaults())
                .oauth2Login(Customizer.withDefaults()); // Enable OAuth2 login


        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new InMemoryUserDetailsManager(
                User.withUsername("testuser")
                        .password("{noop}password") // No encoding for simplicity
                        .authorities("read")
                        .build()
        );
    }


}