package msa.service.auth.util;


public final class RedisKey {
    private RedisKey() {}

    /**
     * 이메일 인증 토큰으로 사용자 정보를 조회하기 위한
     * Redis 키를 생성합니다.
     */
    public static String keyForSignupToken(String token) {
        return "signup::token:" + token;
    }

    /**
     * 로그이웃 jwt 저장용 Redis 키를 생성합니다.
     */
    public static String keyForLogoutToken(String token) {
        return "logout::token:" + token;
     }
}
