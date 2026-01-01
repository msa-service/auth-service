package msa.service.auth.service.request;

public record SignupRequest(
        String email,
        String password
) {
}
