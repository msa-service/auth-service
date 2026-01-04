package msa.service.auth.domain.entity;


import jakarta.persistence.*;
import lombok.*;
import msa.service.auth.domain.enums.AccountState;
import msa.service.auth.domain.enums.LoginType;


@Getter
@Setter
@Entity
@Table(
        name = "account",
        uniqueConstraints = {
                @UniqueConstraint(name = "uk_provider_identifier",
                        columnNames = {"provider", "providerId"}
                )
        }
)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Account {

    @Id
    private Long userId;

    // 사용자의 로그인 정보
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private LoginType provider;

    // 그 때 key, LOCAL의 경우 email.
    @Column(nullable = false)
    private String providerId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AccountState state;

    // LOCAL 전용: 사용자 비밀번호, OAuth 경우: OAUTH
    @Column(nullable = false)
    private String password;

    public static Account create(Long id, LoginType provider, String providerId, String password, AccountState state) {
        Account account = new Account();
        account.userId = id;
        account.provider = provider;
        account.providerId = providerId;
        account.password = password;
        account.state = state;

        return account;
    }

}
