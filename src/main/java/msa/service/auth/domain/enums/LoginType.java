package msa.service.auth.domain.enums;

import com.fasterxml.jackson.annotation.JsonCreator;

public enum LoginType {
    GOOGLE,
    GITHUB;

    // 역직렬화 단게에서 대소문자 무시하고 변환시키기
    @JsonCreator
    public static LoginType from(String data) {
        try {
            return LoginType.valueOf(data.strip().toUpperCase());
        } catch (Exception e) {
            throw new IllegalArgumentException(
                    "LoginType.from(): unsupported login type value = " + data
            );
        }
    }
}
