package msa.service.auth.service;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import msa.service.auth.domain.dto.OauthUserInfo;
import msa.service.auth.domain.entity.Account;
import msa.service.auth.domain.enums.AccountState;
import msa.service.auth.domain.enums.LoginType;
import msa.service.auth.domain.exception.BadRequestException;
import msa.service.auth.domain.exception.InternalServerException;
import msa.service.auth.infra.oauth.OauthLoginStrategy;
import msa.service.auth.infra.oauth.OauthLoginStrategyResolver;
import msa.service.auth.repository.AccountRepository;
import msa.service.auth.service.request.OAuthRequest;
import msa.service.auth.service.request.SignupRequest;
import msa.service.auth.service.response.LoginResponse;
import msa.service.auth.service.response.SignupResponse;
import msa.service.auth.util.RedisKey;
import msa.service.auth.util.Snowflake;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.util.UUID;


@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {
    private final AccountRepository accountRepository;
    private final OauthLoginStrategyResolver oauthLoginStrategyResolver;
    private final PasswordEncoder passwordEncoder;
    private final StringRedisTemplate redisTemplate;
    private final EmailService emailService;

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
                    AccountState.ACTIVE
                    ));

            log.info("AuthService::oAuthLogin - userId={}, CREATE", nowAccount.getUserId());
        }

        log.info("AuthService::oauthLogin - userId={}, SUCCESS", nowAccount.getUserId());

        return LoginResponse.from(nowAccount.getProvider().toString(), nowAccount.getProviderId());
    }

    @Transactional
    public SignupResponse registerPendingUser(SignupRequest request) {
        // 1. id 중복 조회.
        Account account = getAccountByProvider(LoginType.LOCAL, request.email());

        if (account != null) {
            // 회원 가입은 했는데 메일 인증은 하지앟는 경우.
            if (account.getState() == AccountState.PENDING) {
                return SignupResponse.from(
                        account.getUserId(),
                        account.getProviderId(),
                        account.getState()
                );
            }

            // 그 외 아이디 중복
            throw new BadRequestException("user email(%s) duplicate".formatted(request.email()
            ));
        }

        // 2. 비밀 번호 강도 조회.
        validatePassword(request.password());

        // 3. 현재 정보를 db에 저장.
        Account nowAccount = accountRepository.save(Account.create(
                snowflake.nextId(),
                LoginType.LOCAL,
                request.email(),
                passwordEncoder.encode(request.password()),
                AccountState.PENDING
        ));

        // 3. 현재 계정 정보를 redis에 저장.
        String token = UUID.randomUUID().toString();
        saveTempUser(token, request.email());

        // 4. 인증용 메일 전송
        emailService.sendVerificationEmail(request.email(), token);

        return SignupResponse.from(nowAccount.getUserId(),
                nowAccount.getProviderId(), nowAccount.getState());
    }

    @Transactional
    public SignupResponse confirmUserRegistration(String token) {
        // 1. 시간 초과 여부 확인
        String tokenKey = RedisKey.keyForSignupToken(token);

        String userEmail = redisTemplate.opsForValue().get(tokenKey);
        redisTemplate.delete(tokenKey);

        if (userEmail == null) {
            throw new BadRequestException(
                    "AuthService.confirmUserRegistration(): The authentication request has expired."
            );
        }

        // 2. 사용자 정보 조회 후
        Account account = getAccountByProvider(LoginType.LOCAL, userEmail);

        if (account == null) {
            // db 등록은 안되어 있는데 redis에는 저장된 상황.
            throw new InternalServerException(
                    "AuthService.confirmUserRegistration(): User data inconsistency detected."
            );
        }

        // 3. 계정 활성화 및 저장
        account.setState(AccountState.ACTIVE);

        accountRepository.save(account);

        return SignupResponse.from(
                account.getUserId(),
                account.getProviderId(),
                account.getState()
        );
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

    /**
     * 메일 인증 바디 전에 사용자 정보를 임시 저장
     *
     * @param token 현재 사용자의 임시 토큰
     * @param email 현재 사용자의 이메일
     */
    private void saveTempUser(String token, String email) {
        String tokenKey = RedisKey.keyForSignupToken(token);
        redisTemplate.opsForValue().set(tokenKey, email);
        redisTemplate.expire(tokenKey, Duration.ofMinutes(5));
    }
}
