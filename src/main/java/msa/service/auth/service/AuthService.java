package msa.service.auth.service;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import msa.service.auth.domain.dto.OauthUserInfo;
import msa.service.auth.domain.entity.Account;
import msa.service.auth.domain.enums.LoginType;
import msa.service.auth.domain.exception.BadRequestException;
import msa.service.auth.infra.oauth.OauthLoginStrategy;
import msa.service.auth.infra.oauth.OauthLoginStrategyResolver;
import msa.service.auth.repository.AccountRepository;
import msa.service.auth.service.request.OAuthRequest;
import msa.service.auth.service.request.SignupRequest;
import msa.service.auth.service.response.LoginResponse;
import msa.service.auth.service.response.SignupResponse;
import msa.service.auth.util.Snowflake;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {
    private final AccountRepository accountRepository;
    private final OauthLoginStrategyResolver oauthLoginStrategyResolver;
    private final PasswordEncoder passwordEncoder;

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

            log.info("AuthService::oAuthLogin - userId={}, CREATE", nowAccount.getUserId());
        }

        log.info("AuthService::oauthLogin - userId={}, SUCCESS", nowAccount.getUserId());

        return LoginResponse.from(nowAccount.getProvider().toString(), nowAccount.getProviderId());
    }

    @Transactional
    public SignupResponse localSignup(SignupRequest request) {
        // 1. id 중복 조회.
        Account account = getAccountByProvider(LoginType.LOCAL, request.email());

        if (account != null) {
            throw new BadRequestException("user email(%s) duplicate".formatted(request.email()
            ));
        }

        // 2. 비밀 번호 강도 조회.
        validatePassword(request.password());

        // 3. 최종 저장
        Account res = accountRepository.save(Account.create(
                snowflake.nextId(),
                LoginType.LOCAL,
                request.email(),
                passwordEncoder.encode(request.password()),
                "GUEST"
        ));

        return SignupResponse.from(res.getUserId(), res.getRole());
    }

    public Account getAccountByProvider(LoginType loginType, String id) {
        return accountRepository.findByProviderAndProviderId(loginType, id)
                .orElse(null);
    }

    /**
     * 사용자가 입력한 비밀번호가 보안 규칙 통과 여부 확인.
     *
     * @param password 사용자가 제공한 비밀번호
     */
    private void validatePassword(String password) {
        // 1. 빈 비밀번호인 경우.
        if (password == null || password.isBlank()) {
            throw new BadRequestException(
                    "Please enter a password"
            );
        }

        // 2. 비밀번호의 길이는 8이상 16 미만
        if (password.length() < 8 || password.length() > 16) {
            throw new BadRequestException(
                    "Password must be 8 and 16 characters"
            );
        }

        // 3. 대소문자, 숫자, 특수문자 포함
        int bitMask = 0;
        final String ALLOWED_SPECIAL_CHARS = "!@#$%^&*()_+-=";

        for (char ch: password.toCharArray()) {
            if (Character.isUpperCase(ch)) {
                bitMask |= 1;
            } else if (Character.isLowerCase(ch)) {
                bitMask |= (1 << 1);
            } else if (Character.isDigit(ch)) {
                bitMask |= (1 << 2);
            } else if (ALLOWED_SPECIAL_CHARS.indexOf(ch) >= 0) {
                bitMask |= (1 << 3);
            } else {
                throw new BadRequestException(
                        "The allowed Special characters - !@#$%^&*()_+-="
                );
            }
        }

        if (bitMask != 0xf) {
            throw new BadRequestException(
                    "Password must include uppercase, lowercase letters and numbers " +
                            "and special characters(!@#$%^&*()_+-=)"
            );
        }
    }
}
