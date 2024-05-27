package org.example.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import static org.example.entity.user.Permission.*;
import static org.example.entity.user.Role.ADMIN;
import static org.springframework.http.HttpMethod.*;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final AuthenticationProvider authProvider;
    private final JwtAuthenticationFilter jwtAuthFilter;
    private final LogoutHandler logoutHandler;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                //todo
                // Disable the default 'csrf' protection
                .csrf(AbstractHttpConfigurer::disable)

                .authorizeHttpRequests(customize -> customize
                        //todo
                        // Give permission(authorize) to access some URL paths
                        // for any user without authenticate them
                        .requestMatchers("/api/v1/auth/**")
                            .permitAll()

                        //todo
                        // Specified some URL paths
                        // that should require authentication
                        .requestMatchers("/api/v1/demoController/logout")
                            .authenticated()

                        //todo
                        // Authorize to access some URL paths
                        // for only authenticated 'Admin' users
                        .requestMatchers(
                                "/api/v1/admin/**",
                                "/api/v1/demoController/can-access/any-authenticated-admin"
                        ).hasRole(ADMIN.name())
                        .requestMatchers(GET, "/api/v1/admin/get-api")
                            .hasAuthority(ADMIN_READ.name())
                        .requestMatchers(POST, "/api/v1/admin/post-api")
                            .hasAuthority(ADMIN_CREATE.name())
                        .requestMatchers(PUT, "/api/v1/admin/update-api")
                            .hasAuthority(ADMIN_UPDATE.name())
                        .requestMatchers(DELETE, "/api/v1/admin/delete-api")
                            .hasAuthority(ADMIN_DELETE.name())

                        //todo
                        // Tell spring security 'all users' should be authenticated
                        // that send requests from the URL paths
                        // that haven't been specified in any previous configurations
                        .anyRequest()
                            .authenticated()
                )

                //todo
                // Tell spring security configure 'SessionCreationPolicy' as 'Stateless'
                // Cause in here we're using 'stateless authentication mechanism'
                // It means the server doesn't need to remember
                // authentication state(which means whether the user is logged in or not) of the user
                // Instead, it trusts the token provided by the client for authentication
                .sessionManagement(customize -> customize
                        .sessionCreationPolicy(STATELESS)
                )

                //todo
                // specify the 'Authentication Provider' to spring security
                // (It means tell spring security we're using a specific 'Authentication Provider')
                .authenticationProvider(authProvider)

                //todo
                // tell spring security execute the 'JwtAuthenticationFilter'
                // before execute 'UsernamePasswordAuthenticationFilter'
                // Cause I want to make sure before authenticate the 'username' and 'password'
                // that particular 'User' has a valid 'JWT'
                // and we do that validation part in our 'JwtAuthenticationFilter'
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)

                //todo
                // configure logout process
                .logout(customize -> customize
                        .logoutUrl("/api/v1/demoController/logout")
                        .addLogoutHandler(logoutHandler)
                        .logoutSuccessHandler(
                                (request, response, authentication) -> SecurityContextHolder.clearContext()
                        )
                );

        return http.build();
    }

}