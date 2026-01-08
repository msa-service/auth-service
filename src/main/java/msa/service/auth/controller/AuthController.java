package msa.service.auth.controller;

import lombok.RequiredArgsConstructor;
import msa.service.auth.service.AuthService;
import msa.service.auth.service.request.LoginRequest;
import msa.service.auth.service.request.OAuthRequest;
import msa.service.auth.service.request.SignupRequest;
import msa.service.auth.service.response.LoginResponse;
import msa.service.auth.service.response.SignupResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RestController
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/v1/auth/oauth")
    public LoginResponse oauth(@RequestBody OAuthRequest request) {
        return authService.oAuthLogin(request);
    }

    @PostMapping("/v1/auth/login")
    public LoginResponse localLogin(@RequestBody LoginRequest request) {
        return authService.localLogin(request);
    }

    @PostMapping("/v1/auth/signup")
    public ResponseEntity<?> signup(@RequestBody SignupRequest request) {

        // 1. 실제 인증 메일 요청.
        SignupResponse response = authService.registerPendingUser(request);

        return ResponseEntity
                .status(HttpStatus.OK)
                .body(response);
    }

    @GetMapping("/v1/auth/email/verify")
    public ResponseEntity<?> verifyEmail(@RequestParam String token) {
        SignupResponse response = authService.confirmUserRegistration(token);

        return ResponseEntity.ok(response);
    }

    @PostMapping("/v1/auth/validation")
    public ResponseEntity<?> validation() {

        return null;
    }

}
