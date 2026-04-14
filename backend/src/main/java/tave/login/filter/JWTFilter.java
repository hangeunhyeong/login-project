package tave.login.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import tave.login.util.JWTUtil;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

/*
요청 헤더에 포함되어있는 JWT를 검증하는 필터(서블릿 레이어에 도달하기 전, security filter에서 수행)
OncePerRequestFilter는 하나의 HTTP 요청에 대해 한 번만 실행되도록 보장한다.
동일한 request 객체로 forward되는 경우에도 중복 실행되지 않는다.
*/
public class JWTFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authorization = request.getHeader("Authorization");
        if (authorization == null) {
            filterChain.doFilter(request, response);    // 다음 필터로 요청을 넘김
            return;
        }

        if (!authorization.startsWith("Bearer ")) {
            throw new ServletException("Invalid JWT Token");
        }

        // 토큰 파싱
        String accessToken = authorization.split(" ")[1];

        if (JWTUtil.isValid(accessToken, true)) {
            String username = JWTUtil.getUsername(accessToken);
            String role = JWTUtil.getRole(accessToken);

            List<GrantedAuthority> authorities = Collections.singletonList(new SimpleGrantedAuthority(role));   // 권한

            Authentication auth = new UsernamePasswordAuthenticationToken(username, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(auth);

            filterChain.doFilter(request, response);
        }
        else{
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json;charset=UTF-8");
            response.getWriter().write("{\"error\":\"토큰 만료 또는 유효하지 않은 토큰\"}");
        }
    }
}
