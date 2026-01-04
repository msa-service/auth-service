package msa.service.auth.domain.enums;

import com.fasterxml.jackson.annotation.JsonCreator;
import msa.service.auth.domain.exception.BadRequestException;

public enum AccountState {
    PENDING,
    ACTIVE,
    INACTIVE;

    // 역직렬화 단게에서 대소문자 무시하고 변환시키기
    @JsonCreator
    public static AccountState from(String data) {
        try {
            return AccountState.valueOf(data.strip().toUpperCase());
        } catch (Exception e) {
            // 등록되지 않는 enum 값으로 요청한 경우
            throw new BadRequestException(
                    "AccountState.from(): unsupported account state value=" + data
            );
        }
    }
}
