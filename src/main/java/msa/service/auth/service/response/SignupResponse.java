package msa.service.auth.service.response;

import msa.service.auth.domain.entity.Account;
import msa.service.auth.domain.enums.AccountState;

public record SignupResponse(
        Long id,
        String email,
        AccountState state
) {
    public static SignupResponse from(Long id, String email, AccountState state) {
        return new SignupResponse(id, email, state);
    }
}
