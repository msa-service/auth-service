package msa.service.auth.util;


public final class RedisKey {
    private RedisKey() {}

    // 회원 가입 메일 인증 대기 중인 사용자 정보 저장요

    /**
     * 회원 가입 이메일 인증 대기 상태의 Redis 키를 생성합니다.
     */
    public static String keyForSignupPending(String email) {
        return "signup::pending:" + email;
    }

    /**
     * 이메일 인증 토큰으로 사용자 정보를 조회하기 위한
     * Redis 키를 생성합니다.
     */
    public static String keyForSignupToken(String token) {
        return "signup::token:" + token;
    }
}
