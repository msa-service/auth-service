package msa.service.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.json.JsonMapper;
import lombok.AllArgsConstructor;
import lombok.Getter;
import msa.service.auth.service.request.LoginRequest;
import msa.service.auth.service.request.SignupRequest;
import msa.service.auth.service.response.LoginResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.web.client.RestClient;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.*;


class AuthApplicationTests {

	RestClient restClient;

	@BeforeEach
	void setUp() {
		ObjectMapper objectMapper = JsonMapper.builder()
				.propertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
				.build();

		MappingJackson2HttpMessageConverter converter =
				new MappingJackson2HttpMessageConverter(objectMapper);

		this.restClient = RestClient.builder()
				.baseUrl("http://localhost:9005") // 실제 서버 필요
				.messageConverters(c -> {
					c.removeIf(a -> a instanceof MappingJackson2HttpMessageConverter);
					c.add(converter);
				})
				.build();
	}

	@Test
	void shouldFailToAccessSecret_whenUnauthenticated() {

		ResponseEntity<String> res = restClient.get()
				.uri("/v1/test/secret")
				.exchange((req, rsp) -> {
					String body = new String(rsp.getBody().readAllBytes(), StandardCharsets.UTF_8);
					return ResponseEntity.status(rsp.getStatusCode()).body(body);
				} );

		System.out.println(res.getBody());

		assertThat(res.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
	}

	@Test
	void login_test() {
		ResponseEntity<String> raw = restClient.post()
				.uri("/v1/auth/login")
				.accept(MediaType.APPLICATION_JSON)
				.body(
						new LoginRequest(
								"newbie11004@gmail.com",
								"adminAS123!") {
						}
				)
				.retrieve()
				.toEntity(String.class);

		System.out.println("status= " + raw.getStatusCode());
		System.out.println("body= " + raw.getBody());
		assertThat(raw.getStatusCode()).isEqualTo(HttpStatus.OK);
	}

	@Test
	void shouldAccessSecretSuccessfully_whenAuthenticated() {
		signup();

		LoginResponse response = login();

		ResponseEntity<String> res = restClient.get()
				.uri("/v1/test/secret")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + response.accessToken())
				.retrieve()
				.toEntity(String.class);

		System.out.println(res.getBody());

		assertThat(res.getStatusCode()).isEqualTo(HttpStatus.OK);

	}

	@Test
	void shouldFailToAccessSecret_whenJwtExpired() {

		String invalidToken = "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiIyNjk2MTcwODU1MTQ5MTk5MzYiLCJhY2NvdW50X2lkIjoyNjk2MTcwODU1MTQ5MTk5MzYsImFjY291bnRfc3RhdGUiOiJQRU5ESU5HIiwiaWF0IjoxNzY4MzQ5MDY3LCJleHAiOjE3NjgzNDk2Njd9.nOWGVUcx1CZwy_t1bWz6dV9husAdS5L2-OSV-kXMh0E_Rr1Ne0JhkH6jez-S0EoD-7pDZ1ostF5ZvMIu0TYv2w";

		ResponseEntity<String> res = restClient.get()
				.uri("/v1/test/secret")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + invalidToken)
				.exchange((req, rsp) -> {
					String body = new String(rsp.getBody().readAllBytes(), StandardCharsets.UTF_8);
					return ResponseEntity.status(rsp.getStatusCode()).body(body);
				} );

		System.out.println(res.getBody());

		assertThat(res.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
	}

	@Test
	void shouldAllowAccess_whenJwtIsInvalid() {
		String invalidToken = "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiIyNjk2MTcwODU1MTQ5MTk5MzYiLCJhY2NvdW50X2lkIjoyNjk2MTcwODU1MTQ5MTk5MzYsImFjY291bnRfc3RhdGUiOiJQRU5ESU5HIiwiaWF0IjoxNzY4MzQ5MDY3LCJleHAiOjE3NjgzNDk2Njd9.nOWGVUcx1CZwy_t1bWz6dV9husAdS5L2-OSV-kXMh0E_Rr1Ne0JhkH6jez-S0EoD-7pDZ1ostF5ZvMIu0TYv2w";

		ResponseEntity<String> res = restClient.get()
				.uri("/v1/test/allow")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + invalidToken)
				.exchange((req, rsp) -> {
					String body = new String(rsp.getBody().readAllBytes(), StandardCharsets.UTF_8);
					return ResponseEntity.status(rsp.getStatusCode()).body(body);
				} );

		System.out.println(res.getBody());

		assertThat(res.getStatusCode()).isEqualTo(HttpStatus.OK);
	}

	@Test
	void shouldFailToAccessLogin_whenAlreadyAuthenticated() {
		signup();

		LoginResponse response = login();

		System.out.println("LoginResponse: " + response);

		ResponseEntity<String> res = restClient.post()
				.uri("/v1/auth/login")
				.header(HttpHeaders.AUTHORIZATION, "Bearer " + response.accessToken())
				.body(
						new LoginRequest(
								"newbie11004@gmail.com",
								"adminAS123!") {
						}
				)
				.exchange((req, rsp) -> {
					return ResponseEntity.status(rsp.getStatusCode()).build();
				} );

		System.out.println(res.getBody());

		assertThat(res.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
	}

	@Test
	void test_non_domain() {

		// 없는 도메인 테스트 -> 404가 떠야함.
		ResponseEntity<String> res = restClient.get()
				.uri("/v1/hello/world")
				.exchange((req, rsp) ->
						ResponseEntity.status(rsp.getStatusCode()).build());

		assertThat(res.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);

		// post api에 get 요청 -> 405가 떠야함.
		ResponseEntity<String> res1 = restClient.post()
				.uri("/v1/test/allow")
				.exchange((req, rsp) ->
						ResponseEntity.status(rsp.getStatusCode()).build());

		assertThat(res1.getStatusCode()).isEqualTo(HttpStatus.METHOD_NOT_ALLOWED);
	}

	void signup() {
		restClient.post()
				.uri("v1/auth/signup")
				.body(
						new SignupRequest(
								"newbie11004@gmail.com",
								"adminAS123!")
				)
				.retrieve()
				.toBodilessEntity();
	}

	LoginResponse login() {
		return restClient.post()
				.uri("/v1/auth/login")
				.accept(MediaType.APPLICATION_JSON)
				.body(
						new LoginRequest(
								"newbie11004@gmail.com",
								"adminAS123!") {
						}
				)
				.retrieve()
				.body(LoginResponse.class);
	}

	@Test
	void contextLoads() {
	}

	@Getter
	@AllArgsConstructor
	static class LoginRequest {
		String email;
		String password;
	}

}
