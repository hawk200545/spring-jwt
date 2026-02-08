package com.hawk.spring_secuirity.auth;

import com.hawk.spring_secuirity.config.JwtService;
import com.hawk.spring_secuirity.user.Role;
import com.hawk.spring_secuirity.user.User;
import com.hawk.spring_secuirity.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository repository;
    private final JwtService service;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(@NonNull RegisterRequest registerRequest){
        var user = User
                .builder()
                .firstName(registerRequest.getFirstName())
                .LastName(registerRequest.getLastName())
                .email(registerRequest.getEmail())
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                .role(Role.USER)
                .build();

        repository.save(user);

        return AuthenticationResponse
                .builder()
                .token(service.generateToken(user))
                .build();
    }

    public AuthenticationResponse authenticate(@NonNull AuthenticationRequest authenticationRequest){
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        authenticationRequest.getEmail(),
                        authenticationRequest.getPassword()
                )
        );
        var user = repository.findByEmail(authenticationRequest.getEmail())
                .orElseThrow();
        return AuthenticationResponse
                .builder()
                .token(service.generateToken(user))
                .build();
    }
}
