package org.example.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.example.entity.Token.Token;
import org.example.entity.Token.TokenRepository;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter
        //todo
        // every time the users send a requests
        // apply this 'JwtAuthenticationFilter' for each one
        extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final TokenRepository tokenRepository;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        //todo
        // Separate the 'Authorization header' from the other headers in the request
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        final String jwt;
        final String userEmail;

        //todo
        // check if the 'Authorization header' is null or
        // that header is not starts with 'Bearer_' part.
        // Cause a 'bearer token' always like 'Bearer <token>'
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        //todo
        // separate the JWT from the 'bearer token'
        jwt = authHeader.substring(7);

        //todo
        // extract 'user email' from the JWT
        userEmail = jwtService.extractUsername(jwt);

        //todo
        // check if the user email is not null and
        // the user for that email is not already 'authenticated'
        // Cause when the 'SecurityContextHolder.getContext().getAuthentication()' is null
        // it means that user is not yet authenticated
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            //todo
            // fetching the 'user details' from database by 'user email'
            UserDetails userDetails = userDetailsService.loadUserByUsername(userEmail);

            //todo
            // check if the JWT is 'valid token' and 'not revoked'
            if (jwtService.isValidToken(jwt, userDetails) && !isRevokedToken(jwt)) {
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );

                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                //todo
                // update security context holder as
                // that particular user is being authenticated
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response);
    }

    //todo
    // check the token is revoked or not
    private boolean isRevokedToken(String jwt) {
        return tokenRepository.findByToken(jwt)
                .map(Token::isRevoked)
                .orElse(true);
    }
}
