package com.hawk.spring_secuirity.token;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class TokenService {
    private final TokenRepository tokenRepository;

    public boolean isValidToken(String token){
        return tokenRepository.findByToken(token)
                .map(t-> !t.isExpired() && !t.isRevoked())
                .orElse(false);
    }
}
