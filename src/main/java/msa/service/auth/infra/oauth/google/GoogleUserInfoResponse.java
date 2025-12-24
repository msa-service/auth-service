package msa.service.auth.infra.oauth.google;

import jakarta.validation.constraints.NotNull;

public record GoogleUserInfoResponse(
        @NotNull String sub,
        String name,
        String givenName,
        String familyName,
        String picture,
        String email,
        String emailVerified,
        String locale
) {
}
