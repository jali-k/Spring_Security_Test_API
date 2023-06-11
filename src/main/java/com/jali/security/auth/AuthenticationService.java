package com.jali.security.auth;

import com.jali.security.config.Jwtservice;
import com.jali.security.user.Role;
import com.jali.security.user.User;
import com.jali.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final Jwtservice jwtservice;
    private final AuthenticationManager authenticationManager;
    public AuthenticationResponse register(RegisterRequest request) {
        // create a user
        // Save it to the database
        // Return the generated token
        var user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword())) // We need to  encode the password before saving it to the database.
                .role(Role.USER)
                .build();
        repository.save(user);
        var jwtToken = jwtservice.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();

    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
    authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                    request.getEmail(),
                    request.getPassword()
            )
    );
    // If it gets to this point the user is authenticated
    // Then wev will need to generate a token and send it back
    var user = repository.findByEmail(request.getEmail())
            .orElseThrow();
        var jwtToken = jwtservice.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }
}
