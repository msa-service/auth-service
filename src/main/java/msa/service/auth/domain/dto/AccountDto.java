package msa.service.auth.domain.dto;

import msa.service.auth.domain.enums.AccountState;

public record AccountDto (
        Long userId,
        AccountState state
){
    public static AccountDto from(Long userId, AccountState state) {
        return new AccountDto(userId, state);
    }
}
