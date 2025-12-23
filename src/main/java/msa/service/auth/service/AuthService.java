package msa.service.auth.service;


import lombok.RequiredArgsConstructor;
import msa.service.auth.domain.dto.OauthUserInfo;
import msa.service.auth.infra.oauth.OauthLoginStrategy;
import msa.service.auth.infra.oauth.OauthLoginStrategyResolver;
import msa.service.auth.repository.AccountRepository;
import msa.service.auth.service.request.OAuthRequest;
import msa.service.auth.service.response.LoginResponse;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final AccountRepository accountRepository;
    private final OauthLoginStrategyResolver oauthLoginStrategyResolver;

    @Transactional
    public LoginResponse oAuthLogin(OAuthRequest request) {
        OauthLoginStrategy strategy = oauthLoginStrategyResolver.resolve(request.type());

        OauthUserInfo userInfo = strategy.verifyAndExtract(request.authToken());

        return LoginResponse.from(userInfo.userEmail(), "b");
    }

}
