package msa.service.auth.service;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import msa.service.auth.domain.dto.AccountDto;
import msa.service.auth.domain.dto.OauthUserInfo;
import msa.service.auth.domain.entity.Account;
import msa.service.auth.domain.enums.AccountState;
import msa.service.auth.domain.enums.LoginType;
import msa.service.auth.domain.exception.BadRequestException;
import msa.service.auth.domain.exception.InternalServerException;
import msa.service.auth.domain.exception.UnauthorizedException;
import msa.service.auth.infra.oauth.OauthLoginStrategy;
import msa.service.auth.infra.oauth.OauthLoginStrategyResolver;
import msa.service.auth.jwt.JwtProvider;
import msa.service.auth.repository.AccountRepository;
import msa.service.auth.service.request.LoginRequest;
import msa.service.auth.service.request.OAuthRequest;
import msa.service.auth.service.request.RefreshRequest;
import msa.service.auth.service.request.SignupRequest;
import msa.service.auth.service.response.LoginResponse;
import msa.service.auth.service.response.SignupResponse;
import msa.service.auth.util.HashUtil;
import msa.service.auth.util.RedisKey;
import msa.service.auth.util.Snowflake;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.util.Date;
import java.util.UUID;
import java.util.concurrent.TimeUnit;


@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {
    private final AccountRepository accountRepository;
    private final StringRedisTemplate redisTemplate;

    private final OauthLoginStrategyResolver oauthLoginStrategyResolver;

    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;
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

        // 3. jwt 발급
        return createLoginResponse(nowAccount);
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

    public LoginResponse localLogin(LoginRequest request) {

        if (request.email() == null || request.password() == null ||
        request.email().isBlank() || request.password().isBlank()) {
            throw new BadRequestException("Email or password is missing.");
        }

        // 1. 계정 조회.
        Account account = getAccountByProvider(LoginType.LOCAL, request.email());

        if (account == null) {
            throw new UnauthorizedException("Email or password is incorrect.");
        }

        // 2. 비밀번호 검사.
        boolean matches = passwordEncoder.matches(request.password(), account.getPassword());

        if (!matches) {
            throw new UnauthorizedException("Email or password is incorrect.");
        }

        // 3. jwt 발급.
        return createLoginResponse(account);
    }

    @Transactional
    public LoginResponse refreshUser(RefreshRequest request) {
        // 1. rt 검증
        if (!jwtProvider.verifyToken(request.refreshToken())) {
            throw  new BadRequestException("Invalid refresh token: expired");
        }

        // 2. redis에 해당 token 존재 여부 조회.
        // 만료된 rt에 대해서는 실제 사용자 ID 조회 X
        Long userId = jwtProvider.getUserId(request.refreshToken());

        String token = redisTemplate.opsForValue()
                .get(RedisKey.keyForRefreshToken(String.valueOf(userId)));
        String hashedRefresh = HashUtil.sha256(request.refreshToken());

        log.info("token = {}, hashed = {}", token, hashedRefresh);

        if (token == null || !token.equals(hashedRefresh)) {
            throw new BadRequestException(("Invalid refresh token: inconsistency"));
        }

        // 3. 재발급
        Account account = accountRepository.findById(userId)
                .orElseThrow(() -> new BadRequestException("Invalid Account Information"));

        return createLoginResponse(account);
    }

    @Transactional
    public void logout(AccountDto user, String at) {
        // 1. 사용자의 rt 삭제
        redisTemplate.delete(RedisKey.keyForRefreshToken(String.valueOf(user.userId())));

        // 2. 현재 at를 블랙 리스트로 저장
        Date exp = jwtProvider.getExpiration(at);

        long ttlSeconds = (exp.getTime() - new Date().getTime()) / 1000 + 1;

        redisTemplate.opsForValue().set(RedisKey.keyForLogoutToken(at), "1"
                , Duration.ofSeconds(ttlSeconds));
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

    @Value("${jwt.refresh-expiration-ms}")
    private long refreshTokenExpiration;

    /**
     * 현재 로그인한 정보에 대해 jwt 생성
     * 
     * @param account 로그인 계정 정보
     * @return access_token & refresh_token
     */
    private LoginResponse createLoginResponse(Account account) {
        // Account -> AccountDTO;
        AccountDto nowUser = AccountDto.from(account.getUserId(), account.getState());

        // access & refresh token 발급
        LoginResponse response = LoginResponse.from(
                jwtProvider.generateAccessToken(nowUser),
                jwtProvider.generateRefreshToken(nowUser)
        );

        // redis에 refresh token 저장
        String key = RedisKey.keyForRefreshToken(String.valueOf(nowUser.userId()));
        String hashedRefresh = HashUtil.sha256(response.refreshToken());

        long ttl = refreshTokenExpiration + 5 * 1000L; // token 만료시간 +5초.

        redisTemplate.opsForValue().set(key, hashedRefresh, ttl, TimeUnit.MILLISECONDS);

        return response;
    }
}
