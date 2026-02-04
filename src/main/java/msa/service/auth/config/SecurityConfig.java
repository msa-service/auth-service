package msa.service.auth.config;

import lombok.RequiredArgsConstructor;
import msa.service.auth.jwt.JwtAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12); 
    }

    private static final String[] LOGIN_ONCE = {
            "/v1/auth/oauth",
            "/v1/auth/login",
            "/v1/auth/signup"
    };

    private static final String[] PERMIT_ALL = {
            "/v1/auth/email/verify",
            "/v1/test/allow",
    };

    private static final String[] NEED_AUTH = {
            "/v1/auth/logout",
            "/v1/test/secret",
    };

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(Customizer.withDefaults())
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .sessionManagement(config ->
                        config.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth ->
                        auth
                                // 로그인한 유저가 다시 접근하는 것을 예방.
                                .requestMatchers(LOGIN_ONCE).anonymous()
                                .requestMatchers(PERMIT_ALL).permitAll()
                                .requestMatchers(NEED_AUTH).authenticated()
                                // 보호 구간을 넓게 설정
                                .requestMatchers("/v1/auth/**").authenticated()

                                // 그 외 모두 거절
                                .anyRequest().denyAll()
                        )
                .exceptionHandling(e -> e
                        .authenticationEntryPoint((req, res, ex) -> res.sendError(401))
                        .accessDeniedHandler((req, res, ex) -> res.sendError(403)))
                .addFilterBefore(jwtAuthenticationFilter,
                        UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
