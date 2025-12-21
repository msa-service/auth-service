package msa.service.auth.service;


import lombok.RequiredArgsConstructor;
import msa.service.auth.repository.AccountRepository;
import msa.service.auth.service.request.OAuthRequest;
import msa.service.auth.service.response.LoginResponse;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final AccountRepository accountRepository;

    public LoginResponse oAuthLogin(OAuthRequest request) {

        return LoginResponse.from("a", "b");
    }

}
