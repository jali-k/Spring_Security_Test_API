package com.jali.security.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {
    private final JWTAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;
    // At the startup the spring security will try to search for a bean, type security filter chain.
    // This security filter chain is the bean responsible for configuring all the http security of our application

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        // Within the security we can decide what are the urls and paths that we want to secure
        // But in every application we have a white list
        // White List:
            // Some endpoints that does not require any authentication, which are open like creating an acc or login.
        http
                .csrf((csrf) -> csrf.ignoringRequestMatchers("/no-csrf"))// Disabling the csrf
                .authorizeHttpRequests(authz -> authz.requestMatchers("/api/v1/auth/**").permitAll().anyRequest().authenticated()) // The new version of white listing

                /*
                Session management
                    we shouldn't store the state of the seesions. That ensures the each request will be authenticated.
                 */
                .sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(authenticationProvider) // Next we need to implement this authentication provider
                //It is a bean and we need to provide it
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);


        return http.build();
    }

}

// To be continued 1.33.31