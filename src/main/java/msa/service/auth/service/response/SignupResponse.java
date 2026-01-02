package msa.service.auth.service.response;

public record SignupResponse(
        String email,
        String role
) {
    public static SignupResponse from(String email, String role) {
        return new SignupResponse(email, role);
    }
}
