package msa.service.auth.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import msa.service.auth.domain.dto.AccountDto;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtProvider jwtProvider;

    private final static String TOKEN_PREFIX = "Bearer ";

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        // 요청 헤더에서 토큰 파싱
        // 해당 헤더가 없는 경우 null 반환.
        String authorizationHeader = request.getHeader("Authorization");

        String jwt = getToken(authorizationHeader);

        if (jwt == null) {
            filterChain.doFilter(request, response);
            return;
        }

        // jwt 검증
        if (jwtProvider.verifyToken(jwt)) {

            AccountDto principal = jwtProvider.tokenToAccountDto(jwt);

            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    principal,
                    null,
                    Collections.emptyList()
            );

            // SecurityContext 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } else {
            SecurityContextHolder.clearContext();
        }

        // 다음 필터로 이동.
        filterChain.doFilter(request, response);
    }

    private String getToken(String token) {
        if (token != null && token.startsWith(TOKEN_PREFIX)) {
            return token.substring(TOKEN_PREFIX.length());
        }
        return null;
    }
}
