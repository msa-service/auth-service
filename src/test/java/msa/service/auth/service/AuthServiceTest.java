package msa.service.auth.service;

import msa.service.auth.domain.entity.Account;
import msa.service.auth.domain.enums.AccountState;
import msa.service.auth.domain.enums.LoginType;
import msa.service.auth.domain.exception.BadRequestException;
import msa.service.auth.repository.AccountRepository;
import msa.service.auth.service.request.SignupRequest;
import msa.service.auth.util.Snowflake;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;

import static org.mockito.BDDMockito.*;
import static org.assertj.core.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @InjectMocks
    AuthService authService;

    @Mock
    AccountRepository accountRepository;

    private final Snowflake snowflake = new Snowflake();

    @Test
    void duplicatedAccountTest() {
        // given
        Account account = Account.create(
                snowflake.nextId(),
                LoginType.LOCAL,
                "admin",
                "admin",
                AccountState.ACTIVE
        );

        given(accountRepository.findByProviderAndProviderId(LoginType.LOCAL, "admin"))
                .willReturn(Optional.of(account));

        // when & then
        SignupRequest request = new SignupRequest(
                "admin",
                "admin"
        );

        Throwable t = catchThrowable(() -> authService.registerPendingUser(request));

        System.out.println("error message: " + t.getMessage());

        assertThat(t)
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("user email");

    }

    @Test
    void validatePasswordTest() {
        // given
        given(accountRepository.findByProviderAndProviderId(LoginType.LOCAL, "admin"))
                .willReturn(Optional.empty());

        // when & then
        // case1 : 비밀번호 미입력
        assertThatThrownBy(() ->
                authService.registerPendingUser(new SignupRequest(
                        "admin",
                        null
                )))
                .isInstanceOf(BadRequestException.class)
                .hasMessage("Please enter a password");
        assertThatThrownBy(() ->
                authService.registerPendingUser(new SignupRequest(
                        "admin",
                        ""
                )))
                .isInstanceOf(BadRequestException.class)
                .hasMessage("Please enter a password");
        assertThatThrownBy(() ->
                authService.registerPendingUser(new SignupRequest(
                        "admin",
                        " "
                )))
                .isInstanceOf(BadRequestException.class)
                .hasMessage("Please enter a password");

        // case2 : 길이 이상
        assertThatThrownBy(() ->
                authService.registerPendingUser(new SignupRequest(
                        "admin",
                        "1234567"
                )))
                .isInstanceOf(BadRequestException.class)
                .hasMessage("Password must be 8 and 16 characters");
        assertThatThrownBy(() ->
                authService.registerPendingUser(new SignupRequest(
                        "admin",
                        "123456787891234432435545"
                )))
                .isInstanceOf(BadRequestException.class)
                .hasMessage("Password must be 8 and 16 characters");

        // case3 : 허용되지 않는 특수문자를 사용한 경우
        assertThatThrownBy(() ->
                authService.registerPendingUser(new SignupRequest(
                        "admin",
                        "123457689/"
                )))
                .isInstanceOf(BadRequestException.class)
                .hasMessage("The allowed Special characters: !@#$%^&*()_+-=");

        // case4: 대소문자, 숫자, 특수문자 하나라도 누락한 경우.
        assertThatThrownBy(() ->
                authService.registerPendingUser(new SignupRequest(
                        "admin",
                        "asdf1234!" // 대문자 누락
                )))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("Password must include");

        assertThatThrownBy(() ->
                authService.registerPendingUser(new SignupRequest(
                        "admin",
                        "ASDF1234!" // 소문자 누락
                )))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("Password must include");

        assertThatThrownBy(() ->
                authService.registerPendingUser(new SignupRequest(
                        "admin",
                        "asdfASDF!" // 숫자 누락
                )))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("Password must include");

        assertThatThrownBy(() ->
                authService.registerPendingUser(new SignupRequest(
                        "admin",
                        "asdfA1234" // 특수 문자 누락
                )))
                .isInstanceOf(BadRequestException.class)
                .hasMessageContaining("Password must include");

        // 최종 정상 입력
        authService.registerPendingUser(
                new SignupRequest(
                        "admin",
                        "asdfASDF12!"
                )
        );
    }

}