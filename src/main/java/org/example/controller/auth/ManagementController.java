package org.example.controller.auth;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(path = "/api/v1/management")
public class ManagementController {
    @GetMapping
    public String get() {
        return "GET:: management controller";
    }

    @PostMapping
    public String post() {
        return "POST:: management controller";
    }

    @DeleteMapping
    public String delete() {
        return "DELETE:: management controller";
    }

    @PutMapping
    public String put() {
        return "PUT:: management controller";
    }
}
