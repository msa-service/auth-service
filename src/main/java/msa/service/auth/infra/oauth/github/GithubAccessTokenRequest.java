package msa.service.auth.infra.oauth.github;

public record GithubAccessTokenRequest(
        String clientId,
        String clientSecret,
        String code
) {
}
