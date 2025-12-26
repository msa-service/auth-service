package msa.service.auth.infra.oauth;

import msa.service.auth.domain.dto.OauthUserInfo;
import msa.service.auth.domain.enums.LoginType;

public interface OauthLoginStrategy {
    // 해당 전력이 어떤 Oauth을 제공하는지.
    LoginType supports();

    // authCode 사용자 정보를 추출해서 반환해주는 함수.
    OauthUserInfo verifyAndExtract(String authCode);
}
