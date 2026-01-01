package msa.service.auth.controller;

import lombok.RequiredArgsConstructor;
import msa.service.auth.service.AuthService;
import msa.service.auth.service.request.OAuthRequest;
import msa.service.auth.service.request.SignupRequest;
import msa.service.auth.service.response.LoginResponse;
import msa.service.auth.service.response.SignupResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/v1/auth/oauth")
    public LoginResponse oauth(@RequestBody OAuthRequest request) {
        return authService.oAuthLogin(request);
    }

    @PostMapping("/v1/users")
    public ResponseEntity<SignupResponse> signup(@RequestBody SignupRequest request) {

        SignupResponse response = authService.localSignup(request);

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(response);
    }


    @PostMapping("/v1/auth/validation")
    public ResponseEntity<?> validation() {

        return null;
    }

}
