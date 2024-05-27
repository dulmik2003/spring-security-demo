package org.example.controller.auth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.example.dto.AuthenticationRequest;
import org.example.dto.AuthenticationResponse;
import org.example.dto.RegisterRequest;
import org.example.service.AuthenticationService;
import org.example.service.LogoutService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping(path = "/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationService authService;

    @PostMapping(path = "/user/register")
    public ResponseEntity<AuthenticationResponse> userRegister(@RequestBody RegisterRequest request) {
        return ResponseEntity.ok(authService.userRegister(request));
    }

    @PostMapping(path = "/admin/register")
    public ResponseEntity<AuthenticationResponse> adminRegister(@RequestBody RegisterRequest request) {
        return ResponseEntity.ok(authService.adminRegister(request));
    }

    @PostMapping(path = "/authenticate")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody AuthenticationRequest request) {
        return ResponseEntity.ok(authService.authenticate(request));
    }
}
