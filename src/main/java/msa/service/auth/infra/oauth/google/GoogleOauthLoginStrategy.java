package msa.service.auth.infra.oauth.google;

import lombok.RequiredArgsConstructor;
import msa.service.auth.domain.dto.OauthUserInfo;
import msa.service.auth.domain.enums.LoginType;
import msa.service.auth.infra.oauth.OauthLoginStrategy;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * Oauth: https://developers.google.com/identity/protocols/oauth2/web-server
 * OIDC: https://developers.google.com/identity/openid-connect/openid-connect#java
 * 
 * (2025-12-25 기준) 따라서 일련 과정 처리.
 */
@Component
@RequiredArgsConstructor
public class GoogleOauthLoginStrategy implements OauthLoginStrategy {

    private final RestClient restClient;

    @Value("${oauth.google.client-id}")
    private String clientId;

    @Value("${oauth.google.client-secret}")
    private String clientSecret;

    @Value("${oauth.google.redirect-url}")
    private String redirectUrl;

    @Override
    public LoginType supports() {
        return LoginType.GOOGLE;
    }

    @Override
    public OauthUserInfo verifyAndExtract(String authCode) {
        GoogleAccessTokenResponse tokenResponse = getGoogleAccessToken(authCode);

        // 공식문서에 따르면 userinfo.sub() : 각 사용자의 고유한 식별 키.
        GoogleUserInfoResponse userInfo = getUserInformation(tokenResponse.accessToken());

        return OauthUserInfo.from(
                userInfo.email(),
                userInfo.sub()
        );
    }

    /**
     * Google OAuth authorization code를 access token으로 교환한다.
     *
     * @param authCode Google OAuth 인증 과정에서 발급된 authorization code
     * @return Google API 접근에 사용되는 access token.
     */
    private GoogleAccessTokenResponse getGoogleAccessToken(String authCode) {
        String accessTokenApi = "https://oauth2.googleapis.com/token";

        // 인증 코드로 access 토큰 요청하기
        String body = "code=" + authCode +
                "&client_id=" + clientId +
                "&client_secret=" + clientSecret +
                "&redirect_uri=" + redirectUrl +
                "&grant_type=authorization_code";

        GoogleAccessTokenResponse result = restClient.post()
                .uri(accessTokenApi)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(body)
                .retrieve()
                .body(GoogleAccessTokenResponse.class);

        if (result == null || result.accessToken() == null) {
            throw new SecurityException(
                    "GoogleOauthLoginStrategy.verifyAndExtract(): Invalid auth code"
            );
        }

        System.out.println("result: " + result);

        return result;
    }

    /**
     * Google access token를 통하여 사용자 정보를 조회한다.
     *
     * @param accessToken Google Oauth 인증을 통해 발급된 access token.
     * @return 인증된 사용자의 정보
     */
    private GoogleUserInfoResponse getUserInformation(String accessToken) {
        String userInfoApi = "https://openidconnect.googleapis.com/v1/userinfo";

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);

        HttpEntity<String> request = new HttpEntity<>(headers);

        GoogleUserInfoResponse info = restClient.get()
                .uri(userInfoApi)
                .headers(h -> h.setBearerAuth(accessToken))
                .retrieve()
                .body(GoogleUserInfoResponse.class);

        if (info == null || info.sub() == null) {
            throw new IllegalArgumentException(
                    "GoogleOauthLoginStrategy.getUserInformation(): Invalid access token");
        }

        return info;
    }
}
