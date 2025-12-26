package msa.service.auth.infra.oauth.github;


public record GithubAccessTokenResponse(
        String accessToken,
        String tokenType,
        String refreshToken
) {
}
