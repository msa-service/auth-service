package msa.service.auth.jwt;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import msa.service.auth.domain.dto.AccountDto;
import msa.service.auth.domain.enums.AccountState;
import msa.service.auth.util.RedisKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtProvider {

    private final long accessTokenExpiration;

    private final long refreshTokenExpiration;

    private final StringRedisTemplate redisTemplate;

    // 클레임에 들어갈 정보.
    private static final String ACCOUNT_ID = "account_id";
    private static final String ACCOUNT_STATE = "account_state";

    private final Key key;

    public JwtProvider(StringRedisTemplate redisTemplate,
                       @Value("${jwt.secret}") String secret,
                       @Value("${jwt.access-expiration-ms}") long atExp,
                       @Value("${jwt.refresh-expiration-ms}") long rtExp
                       ) {
        this.redisTemplate = redisTemplate;
        this.accessTokenExpiration = atExp;
        this.refreshTokenExpiration = rtExp;

        if (secret == null || secret.isBlank()) {
            throw new IllegalArgumentException("Jwt secret is null");
        }

        key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
    }

    public String generateAccessToken(AccountDto accountDto) {
        return generateToken(accountDto, accessTokenExpiration);
    }

    public String generateRefreshToken(AccountDto accountDto) {
        return generateToken(accountDto, refreshTokenExpiration);
    }

    /**
     * 토큰의 유효성(서명, 만료 여부, 로그아웃 요청된 토큰 여부) 확인
     *
     * @param token 사용자 토큰
     * @return 정상적인 토큰(true)
     */
    public boolean verifyToken(String token) {
        try {
            // 1. 서명 및 만료 여부 둘 다 자동 체크
            getClaims(token);

            // 2. 이미 로그아웃 요청된 토큰 체크
            String tokenKey = RedisKey.keyForLogoutToken(token);
            Boolean hasKey = redisTemplate.hasKey(tokenKey);

            // hasKey = true : 이미 로그아웃 요청한 토큰 -> verify 실패
            return !hasKey;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 토큰을 받아서 계정 정보 반환. 토큰 만료 여부 상관없이 추출.
     *
     * @param token 요청한 토큰
     * @return 계정 정보
     */
    public AccountDto tokenToAccountDto(String token) {
        Claims claims;

        try {
            claims = getClaims(token);
        } catch (ExpiredJwtException e) {
            claims = e.getClaims();
        }

        Long userId = (Long) claims.get(ACCOUNT_ID);
        AccountState accountState = AccountState.from(claims.get(ACCOUNT_STATE).toString());

        return AccountDto.from(userId, accountState);
    }

    public Date getExpiration(String token) {
        if (!verifyToken(token))
            return new Date();

        return getClaims(token).getExpiration();
    }

    private String generateToken(AccountDto account, long expireTime) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + expireTime);

        return Jwts.builder()
                .setSubject(String.valueOf(account.userId()))
                .claim(ACCOUNT_ID, account.userId())
                .claim(ACCOUNT_STATE, account.state())
                .setIssuedAt(now)
                .setExpiration(expiry)
                .signWith(key)
                .compact();
    }

    /**
     * JWT 토큰에서 Claims 정보를 추출한다.
     *
     * @param token JWT 문자열
     * @return 토큰에 포함된 Claims 객체
     *
     * @throws io.jsonwebtoken.security.SecurityException 서명 키 불일치 또는 위조된 서명
     */
    private Claims getClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
