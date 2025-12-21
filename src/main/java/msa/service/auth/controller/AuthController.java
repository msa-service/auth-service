package msa.service.auth.controller;

import lombok.RequiredArgsConstructor;
import msa.service.auth.service.AuthService;
import msa.service.auth.service.request.LoginRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/v1/auth/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        return null;
    }

    @PostMapping("/v1/auth/validation")
    public ResponseEntity<?> validation() {

        return null;
    }

}
