package msa.service.auth.infra.oauth.github;

import lombok.RequiredArgsConstructor;
import msa.service.auth.domain.dto.OauthUserInfo;
import msa.service.auth.domain.enums.LoginType;
import msa.service.auth.infra.oauth.OauthLoginStrategy;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

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
                .body(GithubAccessTokenResponse.class);

        if (result == null || result.accessToken() == null) {
            throw new SecurityException(
                    "GithubOauthLoginStrategy.getGithubAccessToken(): Invalid auth code"
            );
        }

        return result;
    }

    private GithubUserInfoResponse getUserInformation(String accessToken) {
        String userInfoApi = "https://api.github.com/user";

        GithubUserInfoResponse result = restClient.get()
                .uri(userInfoApi)
                .headers(h -> {
                    h.setBearerAuth(accessToken);
                    h.setAccept(List.of(MediaType.APPLICATION_JSON));
                })
                .retrieve()
                .body(GithubUserInfoResponse.class);

        if (result == null || result.id() == null) {
            throw new SecurityException(
                    "GithubOauthLoginStrategy.getUserInformation(): Invalid auth code"
            );
        }

        return result;
    }
}
