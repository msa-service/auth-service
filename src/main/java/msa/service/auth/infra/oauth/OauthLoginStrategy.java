package msa.service.auth.infra.oauth;

import msa.service.auth.domain.enums.LoginType;

public interface OauthLoginStrategy {
    LoginType supports();
    Object verifyAndExtract(String authCode);
}
