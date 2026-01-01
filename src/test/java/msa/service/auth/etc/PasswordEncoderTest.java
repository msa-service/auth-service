package msa.service.auth.etc;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
public class PasswordEncoderTest {

    @Autowired
    PasswordEncoder passwordEncoder;

    @Test
    void passwordEncodeAndMatchTest() {
        // given
        String myPassword = "my-password";

        // when
        String encoded1 = "$2a$10$QVuBQQvIL2mNRlmVYy8duexcek2rRCuVUXZI0wkki/6V3hIeUFDRq";
        String encoded2 = passwordEncoder.encode(myPassword);

        // then
        // 1. 암호화 결과는 매변 달라야 함.
        assertThat(encoded1).isNotEqualTo(encoded2);

        // 2. 둘 다 matches 에서 true 나와야 함.
        assertThat(passwordEncoder.matches(myPassword, encoded1)).isTrue();
        assertThat(passwordEncoder.matches(myPassword, encoded2)).isTrue();

        // 3. 틀린 비번에서 false
        assertThat(passwordEncoder.matches("wrong", encoded1)).isFalse();

        System.out.println("pw1: " + encoded1);
        System.out.println("pw2: " + encoded2);
    }
}
