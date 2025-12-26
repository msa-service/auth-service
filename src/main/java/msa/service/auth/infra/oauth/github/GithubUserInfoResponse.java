package msa.service.auth.infra.oauth.github;

/**
 * 출처 : https://docs.github.com/en/rest/users/users?apiVersion=2022-11-28
 */
public record GithubUserInfoResponse(
        String login,
        String id
) {
}
