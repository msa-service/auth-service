package msa.service.auth.infra.oauth.google;

public record GoogleErrorResponse(
        String error,
        String errorDescription
) {
}
