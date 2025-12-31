package msa.service.auth.infra.oauth.google;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import msa.service.auth.domain.dto.OauthUserInfo;
import msa.service.auth.domain.enums.LoginType;
import msa.service.auth.domain.exception.ApiBadGateway;
import msa.service.auth.domain.exception.BadRequestException;
import msa.service.auth.domain.exception.InternalServerException;
import msa.service.auth.infra.oauth.OauthLoginStrategy;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.util.StreamUtils;
import org.springframework.web.client.RestClient;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

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
    private final ObjectMapper objectMapper;

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

        // 성공시 200, 실패시 4xx
        GoogleAccessTokenResponse result = restClient.post()
                .uri(accessTokenApi)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(body)
                .retrieve()
                .onStatus(HttpStatusCode::is4xxClientError,
                        handle4xxError("GoogleOauthLoginStrategy.verifyAndExtract()"))
                .onStatus(HttpStatusCode::is5xxServerError, handle5xxError("token"))
                .body(GoogleAccessTokenResponse.class);

        if (result == null || result.accessToken() == null) {
            throw new BadRequestException(
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
                .onStatus(HttpStatusCode::is4xxClientError,
                        handle4xxError("GoogleOauthLoginStrategy.getUserInformation()"))
                .onStatus(HttpStatusCode::is5xxServerError, handle5xxError("userinfo"))
                .body(GoogleUserInfoResponse.class);

        if (info == null || info.sub() == null) {
            throw new BadRequestException(
                    "GoogleOauthLoginStrategy.getUserInformation(): Invalid access token");
        }

        return info;
    }

    /**
     * authCode -> accessToken을 요청하는 과정에서 4xx 상태 코드가 반환되는 경우
     * accessToken -> information을 요청하는 과정에서 4xx 상태 코드가 반환되는 경우
     * 이를 client로 전달될 실제 에러 처리 handler 제공
     *
     * @param where 에러가 발생한 위치
     * @return ErrorHandler
     */
    private RestClient.ResponseSpec.ErrorHandler handle4xxError(String where) {
        return (req, res) -> {
            try {
                String raw = StreamUtils.copyToString(res.getBody(), StandardCharsets.UTF_8);

                GoogleErrorResponse error =
                        objectMapper.readValue(raw, GoogleErrorResponse.class);

                // GoogleErrorResponse format 변경됨.
                if (error.error() == null) {
                    throw new InternalServerException(
                            where + ": failed to read google error response"
                    );
                }

                throw new BadRequestException(
                        where + ": " + error.error()
                );
            } catch(IOException e) {
                // objectMapper error -> GoogleErrorResponse change.
                throw new InternalServerException(
                        where + ": failed to read google error response"
                );
            }
        };
    }

    /**
     * authCode -> accessToken을 요청하는 과정에서 5xx 상태 코드가 반환되는 경우
     * accessToken -> information을 요청하는 과정에서 5xx 상태 코드가 반환되는 경우
     * 이를 client로 전달될 실제 에러 처리 handler 제공
     *
     * @param api 에러를 반환한 실제 요청한 api 명
     * @return ErrorHandler
     */
    private RestClient.ResponseSpec.ErrorHandler handle5xxError(String api) {
        return (req, res) -> {
            throw new ApiBadGateway(
                    "Google " + api + " service is temporarily unavailable.");
        };
    }
}