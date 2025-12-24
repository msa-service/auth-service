package msa.service.auth.infra.oauth.google;

import lombok.RequiredArgsConstructor;
import msa.service.auth.domain.dto.OauthUserInfo;
import msa.service.auth.domain.enums.LoginType;
import msa.service.auth.infra.oauth.OauthLoginStrategy;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

/**
 * Oauth: https://developers.google.com/identity/protocols/oauth2/web-server
 * OIDC: https://developers.google.com/identity/openid-connect/openid-connect#java
 * 
 * 따라서 사용자 정보 획득
 */
@Component
@RequiredArgsConstructor
public class GoogleOauthLoginStrategy implements OauthLoginStrategy {

    private final RestTemplate restTemplate;

    @Value("${google.oauth.client-id}")
    private String clientId;

    @Value("${google.oauth.client-secret}")
    private String clientSecret;

    @Value("${google.oauth.redirect-url}")
    private String redirectUrl;

    @Override
    public LoginType supports() {
        return LoginType.GOOGLE;
    }

    @Override
    public OauthUserInfo verifyAndExtract(String authCode) {
        GoogleTokenResponse tokenResponse = getGoogleAccessToken(authCode);

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
     *
     */
    private GoogleTokenResponse getGoogleAccessToken(String authCode) {
        String accessTokenApi = "https://oauth2.googleapis.com/token";

        // 1. 인증 코드로 access 토큰 요청하기
        HttpHeaders headers = new HttpHeaders();

        String body = "code=" + authCode +
                "&client_id=" + clientId +
                "&redirect_url=" + redirectUrl +
                "&grant_type=authorization_code";


        HttpEntity<String> request = new HttpEntity<>(body, headers);

        try {
            // authCode -> accessToken 발급
            ResponseEntity<GoogleTokenResponse> response = restTemplate.exchange(
                    accessTokenApi,
                    HttpMethod.POST,
                    request,
                    GoogleTokenResponse.class
            );

            GoogleTokenResponse result = response.getBody();

            // 발급 실패 -> authCode 오류
            if (result == null || result.accessToken() == null) {
                throw new SecurityException(
                        "GoogleOauthLoginStrategy.verifyAndExtract(): Invalid auth code"
                );
            }

            return result;
        } catch (HttpClientErrorException e) {
            throw new IllegalArgumentException(
                    "GoogleOauthLoginStrategy.verifyAndExtract(): Invalid auth code");
        }
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

        try {
            ResponseEntity<GoogleUserInfoResponse> res = restTemplate.exchange(
                    userInfoApi,
                    HttpMethod.GET,
                    request,
                    GoogleUserInfoResponse.class
            );

            GoogleUserInfoResponse info = res.getBody();

            if (info == null) {
                throw new IllegalArgumentException(
                        "GoogleOauthLoginStrategy.getUserInformation(): Invalid access token");
            }

            return info;
        } catch (Exception e) {
            throw new IllegalArgumentException(
                    "GoogleOauthLoginStrategy.getUserInformation(): Invalid access token"
            );
        }

    }
}
