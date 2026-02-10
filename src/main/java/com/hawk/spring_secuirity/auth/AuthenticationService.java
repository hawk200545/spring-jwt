package com.hawk.spring_secuirity.auth;

import com.hawk.spring_secuirity.config.JwtService;
import com.hawk.spring_secuirity.token.Token;
import com.hawk.spring_secuirity.token.TokenRepository;
import com.hawk.spring_secuirity.token.TokenType;
import com.hawk.spring_secuirity.user.Role;
import com.hawk.spring_secuirity.user.User;
import com.hawk.spring_secuirity.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository repository;
    private final TokenRepository tokenRepository;
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
        
        var savedUser = repository.save(user);
        var generatedToken = service.generateToken(user);

        saveToken(generatedToken, savedUser);
        return AuthenticationResponse
                .builder()
                .token(generatedToken)
                .build();
    }

    private void saveToken(String generatedToken, User savedUser) {
        var token = Token.
                builder()
                .token(generatedToken)
                .type(TokenType.Bearer)
                .expired(false)
                .revoked(false)
                .user(savedUser)
                .build();
        tokenRepository.save(token);
    }

    private void revokeAllUserTokens(User user){
        List<Token> validUserTokens = tokenRepository.findAllValidTokenByUser(user.getId());
        if(validUserTokens.isEmpty()) return;
        validUserTokens.forEach(t->{
            t.setExpired(true);
            t.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
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
        var generatedToken = service.generateToken(user);
        revokeAllUserTokens(user);
        saveToken(generatedToken,user);
        return AuthenticationResponse
                .builder()
                .token(generatedToken)
                .build();
    }
}
