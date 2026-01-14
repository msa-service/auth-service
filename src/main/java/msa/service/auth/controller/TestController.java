package msa.service.auth.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/v1/test/allow")
    public ResponseEntity<String> allow() {
        return ResponseEntity.ok("this is allow.");
    }

    @GetMapping("/v1/test/secret")
    public ResponseEntity<String> secret() {
        return ResponseEntity.ok("you can read this.");
    }
}
