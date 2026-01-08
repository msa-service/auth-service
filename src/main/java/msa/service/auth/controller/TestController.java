package msa.service.auth.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/v1/api/allow")
    public ResponseEntity<?> allow() {
        return ResponseEntity.ok("this is allow.");
    }

    @GetMapping("/v1/api/secret")
    public ResponseEntity<?> secret() {
        return ResponseEntity.ok("you can read this.");
    }
}
