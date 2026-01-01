package msa.service.auth.infra.oauth.github;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import msa.service.auth.domain.dto.OauthUserInfo;
import msa.service.auth.domain.enums.LoginType;
import msa.service.auth.domain.exception.ApiBadGateway;
import msa.service.auth.domain.exception.BadRequestException;
import msa.service.auth.domain.exception.InternalServerException;
import msa.service.auth.infra.oauth.OauthLoginStrategy;
import msa.service.auth.infra.oauth.google.GithubErrorResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.StreamUtils;
import org.springframework.web.client.RestClient;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * https://docs.github.com/ko/apps/overview
 *
 * (2025-12-25 기준) 따라서 일련 과정 처리.
 */
@Component
@RequiredArgsConstructor
public class GithubOauthLoginStrategy implements OauthLoginStrategy {

    private final RestClient restClient;
    private final ObjectMapper objectMapper;

    @Value("${oauth.github.client-id}")
    private String clientId;

    @Value("${oauth.github.client-secret}")
    private String clientSecret;

    @Override
    public LoginType supports() {
        return LoginType.GITHUB;
    }

    @Override
    public OauthUserInfo verifyAndExtract(String authCode) {

        // code -> access token
        GithubAccessTokenResponse token = getGithubAccessToken(authCode);

        GithubUserInfoResponse info = getUserInformation(token.accessToken());

        return OauthUserInfo.from(info.login(), info.id());
    }

    /**
     * GitHub OAuth authorization code를 access token으로 교환한다.
     *
     * @param authCode GitHub OAuth 인증 과정에서 발급된 authorization code
     * @return Github API 접근에 사용되는 access token.
     */
    private GithubAccessTokenResponse getGithubAccessToken(String authCode) {
        String accessTokenApi = "https://github.com/login/oauth/access_token";

        GithubAccessTokenResponse result = restClient.post()
                .uri(accessTokenApi)
                .headers(h -> h.setAccept(List.of(MediaType.APPLICATION_JSON)))
                .body(new GithubAccessTokenRequest(clientId, clientSecret, authCode))
                .retrieve()
                .onStatus(HttpStatusCode::is4xxClientError,
                        handle4xxError("GithubOauthLoginStrategy.getGithubAccessToken()"))
                .onStatus(HttpStatusCode::is5xxServerError,
                        handle5xxError("access_token"))
                .body(GithubAccessTokenResponse.class);

        if (result == null || result.accessToken() == null) {
            throw new BadRequestException(
                    "GithubOauthLoginStrategy.getGithubAccessToken(): Invalid auth code"
            );
        }

        return result;
    }

    /**
     * Github access token을 사용하여 사용자 정보를 조회
     *
     * @param accessToken Github Oauth을 통하여 발급된 access token.
     * @return 인증된 사용자 정보
     */
    private GithubUserInfoResponse getUserInformation(String accessToken) {
        String userInfoApi = "https://api.github.com/user";

        GithubUserInfoResponse result = restClient.get()
                .uri(userInfoApi)
                .headers(h -> {
                    h.setBearerAuth(accessToken);
                    h.setAccept(List.of(MediaType.APPLICATION_JSON));
                })
                .retrieve()
                .onStatus(HttpStatusCode::is4xxClientError,
                        handle4xxError("GithubOauthLoginStrategy.getUserInformation()"))
                .onStatus(HttpStatusCode::is5xxServerError, handle5xxError("user"))
                .body(GithubUserInfoResponse.class);

        if (result == null || result.id() == null) {
            throw new SecurityException(
                    "GithubOauthLoginStrategy.getUserInformation(): Invalid auth code"
            );
        }

        return result;
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

                GithubErrorResponse error =
                        objectMapper.readValue(raw, GithubErrorResponse.class);

                // GithubErrorResponse format 변경됨.
                if (error.error() == null) {
                    throw new InternalServerException(
                            where + ": failed to read github error response"
                    );
                }

                throw new BadRequestException(
                        where + ": " + error.error()
                );
            } catch(IOException e) {
                // objectMapper error -> GithubErrorResponse change.
                throw new InternalServerException(
                        where + ": failed to read github error response"
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
                    "Github " + api + " service is temporarily unavailable.");
        };
    }
}
