package msa.service.auth.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailService {

    private final JavaMailSender mailSender;

    @Value("${app.base-url}")
    private String baseUrl;

    @Value("${app.email-verify}")
    private String apiUrl;

    public void sendVerificationEmail(String to, String token) {
        String verifyLink = baseUrl + apiUrl;

        String subject = "이메일 인증을 완료 해주세요.";
        String text = "아래 링크를 클릭하여 이메일 인증을 완료하세요.\n" + verifyLink;

        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject(subject);
        message.setText(text);

        mailSender.send(message);
    }

}
