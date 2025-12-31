package msa.service.auth.infra.oauth.github;

public record GithubErrorResponse(
        String error,
        String errorDescription
) {
}
