package org.example.controller.auth;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(path = "/api/v1/admin")
public class AdminController {
    @GetMapping(path = "/get-api")
    public String get() {
        return "GET:: admin controller";
    }

    @PostMapping(path = "/post-api")
    public String post() {
        return "POST:: admin controller";
    }

    @DeleteMapping(path = "/delete-api")
    public String delete() {
        return "DELETE:: admin controller";
    }

    @PutMapping(path = "/update-api")
    public String put() {
        return "UPDATE:: admin controller";
    }
}
