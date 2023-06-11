package com.jali.security.config;

import com.jali.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration // Since this is a configuration, spring will first pick up this class and implement and inject all the beans that we are implementing in this configuration
// That's why wev add this configuration annotation
@RequiredArgsConstructor

public class ApplicationConfig {
    private final UserRepository repository;

    @Bean // The following is a bean
    public UserDetailsService userDetailsService(){
        return username -> repository.findByEmail(username) // Trying to get that user from the database
                .orElseThrow(()-> new UsernameNotFoundException("User Not Found"));
    }

    @Bean
    public AuthenticationProvider authenticationProvider(){
        // This authentication provider is the data access object which is responsible to fetch user details and encode password...
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService()); // We need to specify which user details service we are using, we have that method in above
        authProvider.setPasswordEncoder(passwordEncorder()); // Tells how do we encode the password.
   return authProvider;
    }

    // Responsible for authentication

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncorder() {
        return new BCryptPasswordEncoder();
    }


}
