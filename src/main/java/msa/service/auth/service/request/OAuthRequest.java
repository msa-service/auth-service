package msa.service.auth.service.request;

import msa.service.auth.domain.enums.LoginType;

public record OAuthRequest(String authToken, LoginType type) {
}
