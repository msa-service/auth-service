package msa.service.auth.infra.oauth.google;


/**
 * 출처 : https://developers.google.com/identity/protocols/oauth2/web-server
 * authCode를 통하여 google api에 접근용 access token을 받을 때 response
 */
public record GoogleAccessTokenResponse(
        String accessToken,
        Integer expiresIn,
        String tokenType,
        String scope,
        String refreshToken
){
}
