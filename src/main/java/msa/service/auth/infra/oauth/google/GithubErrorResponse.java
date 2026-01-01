package msa.service.auth.infra.oauth.google;

public record GithubErrorResponse(
        String error,
        String errorDescription
) {
}
