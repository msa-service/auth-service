package msa.service.auth.domain.dto;

public record OauthUserInfo(
        String userEmail,
        String userProviderId
) {
    public static OauthUserInfo from(String email, String key) {
        return new OauthUserInfo(email, key);
    }
}
