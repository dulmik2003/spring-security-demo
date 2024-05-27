package org.example.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.example.config.JwtService;
import org.example.dto.AuthenticationRequest;
import org.example.dto.AuthenticationResponse;
import org.example.dto.RegisterRequest;
import org.example.entity.Token.Token;
import org.example.entity.Token.TokenRepository;
import org.example.entity.Token.TokenType;
import org.example.entity.user.Role;
import org.example.entity.user.User;
import org.example.entity.user.UserRepository;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository userRepository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authManager;


    //todo
    // Register 'user' to the system
    public AuthenticationResponse userRegister(RegisterRequest request) {
        //todo
        // create a user and store it in the database
        User user = User.builder()
                .firstName(request.getFirstname())
                .lastName(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
        userRepository.save(user);

//        //todo
//        // generate a JWT
//        String generatedJWT = jwtService.generateJWT(user);

//        //todo
//        // generate a 'refresh token'
//        String generatedRefToken = jwtService.generateRefreshToken(user);

//        //todo
//        // create a 'token object' and store it in the database
//        saveUserToken(user, generatedJWT);

        return AuthenticationResponse.builder()
//                .accessToken(generatedJWT)
//                .refreshToken(generatedRefToken)
                .message("User registered successfully...")
                .build();
    }


    private void saveUserToken(User user, String jwt) {
        Token token = Token.builder()
                .user(user)
                .token(jwt)
                .tokenType(TokenType.BEARER)
                .isRevoked(false)
                .build();
        tokenRepository.save(token);
    }


    //todo
    // register an 'admin' to the system
    public AuthenticationResponse adminRegister(RegisterRequest request) {
        User user = User.builder()
                .firstName(request.getFirstname())
                .lastName(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.ADMIN)
                .build();
        userRepository.save(user);

//        //todo
//        // generate a JWT
//        String generatedToken = jwtService.generateJWT(user);

//        //todo
//        // create a 'token object' and store it in the database
//        saveUserToken(user, generatedToken);

        return AuthenticationResponse.builder()
                .message("Admin User registered successfully...")
//                .accessToken(generatedToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        //todo
        // authenticate username and password
        authManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        //todo
        // fetching user from the database from the email
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow();

        //todo
        // add extra claims to the token
        HashMap<String, Object> extraClaims = new HashMap<>();
        extraClaims.put("fst", user.getFirstName());
        extraClaims.put("lst", user.getLastName());
        extraClaims.put("rol", user.getRole());

        //todo
        // generate a JWT
        String generatedToken = jwtService.generateJWT(user);

//        //todo
//        // generate a 'refresh token'
//        String generatedRefToken = jwtService.generateRefreshToken(user);

        //todo
        // revoke all previous tokens before storing a new one to the database
        revokeAllUserTokens(user);

        //todo
        // create a 'token object' and store it in the database
        saveUserToken(user, generatedToken);

        return AuthenticationResponse.builder()
                .accessToken(generatedToken)
//                .refreshToken(generatedRefToken)
                .message("User authenticate successfully...")
                .build();
    }

    private void revokeAllUserTokens(User user) {
        List<Token> validUserTokens = tokenRepository.findAllValidTokensByUser(user.getId());

        if (validUserTokens.isEmpty()) {
            return;
        }
        validUserTokens.forEach(token -> {
            token.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }

    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        final String refreshToken;
        final String userEmail;


        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return;
        }

        //todo
        // separate the 'refresh token' from 'authorization header'
        refreshToken = authHeader.substring(7);

        //todo
        // extract the 'user email' from 'refresh token'
        userEmail = jwtService.extractUsername(refreshToken);

        if (userEmail != null) {
            //todo
            // fetching the 'user' from database by 'user email'
            User user = userRepository.findByEmail(userEmail)
                    .orElseThrow();

            //todo
            // check if the  the 'refresh token' is valid or not
            if (jwtService.isValidToken(refreshToken, user)) {
                String generatedAccessToken = jwtService.generateJWT(user);

                //todo
                // revoke all previous tokens before storing a new one to the database
                revokeAllUserTokens(user);

                //todo
                // create a 'token object' and store it in the database
                saveUserToken(user, generatedAccessToken);

                AuthenticationResponse authResponse = AuthenticationResponse.builder()
                        .accessToken(generatedAccessToken)
                        .refreshToken(refreshToken)
                        .build();

                new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
            }
        }
    }
}
