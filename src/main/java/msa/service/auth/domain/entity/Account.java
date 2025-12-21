package msa.service.auth.domain.entity;


import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.*;


@Getter
@Setter
@Entity
@Table(name = "account")
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Account {

    @Id
    private Long userId;

    @Column(nullable = false, unique = true)
    private String email;

    // oAuth 가입자의 경우 OAUTH 문자열이 들어가게됨.
    @Column(nullable = false)
    private String password;

    @Column
    private String userName;

    @Column
    private String role;
}
