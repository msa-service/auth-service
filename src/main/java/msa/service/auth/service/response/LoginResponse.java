package msa.service.auth.service.response;

public record LoginResponse(
        String accessToken, String refreshToken) {
    public static LoginResponse from(String at, String rt) {
        return new LoginResponse(at, rt);
    }
}
