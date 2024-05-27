package org.example.controller.demo;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.example.service.LogoutService;
import org.example.service.AuthenticationService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

@RestController
@RequiredArgsConstructor
@RequestMapping(path = "/api/v1/demoController")
public class DemoController {
    private final AuthenticationService authService;
    private final LogoutService logoutService;

    @GetMapping("/can-access/any-authenticated-user")
    public ResponseEntity<String> sayHelloToUser() {
        return ResponseEntity.ok("Hello this api end point can be access by 'any role'");
    }
    @GetMapping("/can-access/any-authenticated-admin")
    public ResponseEntity<String> sayHelloToAdmin() {
        return ResponseEntity.ok("Hello this api end point can be access by 'admin role'");
    }

    @PostMapping(path = "/refresh-token")
    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        authService.refreshToken(request, response);
    }

    @GetMapping("/logout")
    public void logout(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) {
        logoutService.logout(request, response, authentication);
    }
}
