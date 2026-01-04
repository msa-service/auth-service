package msa.service.auth.service.request;

public record LoginRequest(
        String email,
        String password
){
}
