package org.example.service;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.example.entity.Token.Token;
import org.example.entity.Token.TokenRepository;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class LogoutService implements LogoutHandler {
    private final TokenRepository tokenRepository;

    @Override
    public void logout(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String jwt;

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return;
        }
        jwt = authHeader.substring(7);

        //todo
        // find the only active token
        Token onlyUnrevokedToken = tokenRepository.findByToken(jwt)
                .orElse(null);

        if (onlyUnrevokedToken == null) {
            return;
        }

        //todo
        // revoke the only active token
        // and save it in the database
        // before logout from the system
        onlyUnrevokedToken.setRevoked(true);
        tokenRepository.save(onlyUnrevokedToken);
    }
}
