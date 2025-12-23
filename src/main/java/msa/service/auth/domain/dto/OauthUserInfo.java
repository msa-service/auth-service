package msa.service.auth.domain.dto;

public record OauthUserInfo(
        String userEmail
) {
    public static OauthUserInfo from(String email) {
        return new OauthUserInfo(email);
    }
}
