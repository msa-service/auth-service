package msa.service.auth.entity;


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

    @Column
    private String userName;

    @Column
    private String role;
}
