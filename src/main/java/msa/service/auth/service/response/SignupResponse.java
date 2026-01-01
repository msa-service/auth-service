package msa.service.auth.service.response;

public record SignupResponse(
        Long id,
        String role
) {
    public static SignupResponse from(Long id, String role) {
        return new SignupResponse(id, role);
    }
}
