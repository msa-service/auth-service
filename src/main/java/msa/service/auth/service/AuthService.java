package msa.service.auth.service;


import lombok.RequiredArgsConstructor;
import msa.service.auth.domain.dto.OauthUserInfo;
import msa.service.auth.domain.entity.Account;
import msa.service.auth.domain.enums.LoginType;
import msa.service.auth.infra.oauth.OauthLoginStrategy;
import msa.service.auth.infra.oauth.OauthLoginStrategyResolver;
import msa.service.auth.repository.AccountRepository;
import msa.service.auth.service.request.OAuthRequest;
import msa.service.auth.service.response.LoginResponse;
import msa.service.auth.util.Snowflake;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.InvalidKeyException;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final AccountRepository accountRepository;
    private final OauthLoginStrategyResolver oauthLoginStrategyResolver;
    private final Snowflake snowflake = new Snowflake();

    @Transactional
    public LoginResponse oAuthLogin(OAuthRequest request) {
        // 1. OauthLoginStrategy 에 토튼 검증 위임.
        OauthLoginStrategy strategy = oauthLoginStrategyResolver.resolve(request.type());

        // 이메일 정보와 key 정보 획득.
        OauthUserInfo userInfo = strategy.verifyAndExtract(request.authToken());

        // 2. 계정 정보 조회.
        Account nowAccount = getAccountByProvider(request.type(), userInfo.userProviderId());


        if (nowAccount == null) {
            // 기존 회원 X -> 새로가입.

            nowAccount = accountRepository.save(Account.create(
                    snowflake.nextId(),
                    request.type(),
                    userInfo.userProviderId(),
                    "OAUTH",
                    "ADMIN")
            );
        }

        return LoginResponse.from(nowAccount.getProvider().toString(), nowAccount.getProviderId());
    }

    public Account getAccountByProvider(LoginType loginType, String id) {
        return accountRepository.findByProviderAndProviderId(loginType, id)
                .orElse(null);
    }

}
