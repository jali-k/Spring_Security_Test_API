package com.jali.security.config;

// This is the filter that a request hit first.
// To make this a filter we need to extend the class called once per request filter.
// There are many ways actually & this is one way.
// And it will be a filter for each and every request

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.antlr.v4.runtime.misc.NotNull;
import org.hibernate.annotations.NotFound;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

// Then we need to make this class a spring managed bean. For that we need to add @Component or @service annotation.
/*
* A spring bean is  an object that is managed by the spring framework's Inversion of control (IoC) container. Spring beans are java objects that are instantiated, assembled, and managed by the spring container.
* The term "Bean" is refers to a managed object or component in this context*
* */
@Component
@RequiredArgsConstructor // This will create a constructor with any final field we declare
/*
* final variables are like constatnts. That the value once assigned, can't be changed.
* If a method is final, it can't be overridden by a subclass.
* */
public class JWTAuthenticationFilter extends OncePerRequestFilter {

    private final Jwtservice jwtservice;

    @Override
    protected void doFilterInternal(
            // These parameters should not be null. Hence we have to add @Notnull annotation for these.
            @NotNull HttpServletRequest request, // The request we get
            @NotNull HttpServletResponse response, // The response we send
            @NotNull FilterChain filterChain // A list of other filters that we need to execute. when we call this filter.filter it will call the next filter in the chain.
    ) throws ServletException, IOException {
        // The first thing that this filter does is checking whether the request has a token. Here I am going to implement that.
        final String authHeader = request.getHeader("Authorization");// we make a call we need to pass the token in the authentication header. So with this variable we are trying to extract that header.
        // This "Authorization" is the header name that the authentication token or the Bearer taken (We also call it like that) is in.
        final String jwt; // Here we are going to check if there is a token.
        final String userEmail; // That is the userName in our application
        if(authHeader == null || authHeader.startsWith("Bearer ")){ // Here note that the authHeader always starts with the string "Bearer ".
            filterChain.doFilter(request, response); // Here if we make any of the above condition true, we pass the request and the response to the next filter
            return; // Here we need to have return bcz we do not need to execute the below
        }
        // Next trying to extract the token from that above header
        jwt = authHeader.substring(7); // Take a substring starts with position no. 7, bcz it contains "Bearer "

        // After having the token we need to call the UserDetailsService to check weather we are having that user in the database.
        // To do that we need to call the JwtService to extract userName.
        // For that we need a class that can handle the token. We gonna coll that class, "JwtService".
        userEmail = jwtservice.extractUsername(jwt);
    }
}
