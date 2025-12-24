package msa.service.auth.repository;

import msa.service.auth.domain.entity.Account;
import msa.service.auth.domain.enums.LoginType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AccountRepository extends JpaRepository<Account, Long> {

    Optional<Account> findByProviderAndProviderId(LoginType provider, String providerId);

    boolean existsByProviderAndProviderId(LoginType provider, String providerId);
}
