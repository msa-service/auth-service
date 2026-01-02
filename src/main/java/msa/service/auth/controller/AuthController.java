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

import java.util.Map;

@RestController
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/v1/auth/oauth")
    public LoginResponse oauth(@RequestBody OAuthRequest request) {
        return authService.oAuthLogin(request);
    }

    @PostMapping("/v1/users")
    public ResponseEntity<?> signup(@RequestBody SignupRequest request) {

        // 1. 실제 인증 메일 요청.
        authService.localSignup(request);

        Map<String, Object> body = Map.of(
                "status", "PENDING_EMAIL_VERIFICATION",
                "message", "입력하신 이메일로 이즌 메일을 전송했습니다.",
                "email", request.email()
        );

        return ResponseEntity
                .status(HttpStatus.OK)
                .body(body);
    }


    @PostMapping("/v1/auth/validation")
    public ResponseEntity<?> validation() {

        return null;
    }

}
