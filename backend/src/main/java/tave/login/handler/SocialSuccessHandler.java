package tave.login.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import tave.login.domain.jwt.service.JwtService;
import tave.login.util.JWTUtil;

import java.io.IOException;
/*
소셜 로그인 성공
→ 백엔드가 refresh 쿠키 + redirect 응답
→ 브라우저가 /cookie 페이지로 이동
→ 프론트가 재발급 요청 → 백엔드가 access token 발급
→ 프론트가 이후 헤더에 access token 사용

refresh : 쿠키
access : 헤더(Web storage or 메모리)
 */
@Component
@Qualifier("SocialSuccessHandler")
public class SocialSuccessHandler implements AuthenticationSuccessHandler {
    private final JwtService jwtService;

    public SocialSuccessHandler(JwtService jwtService) {
        this.jwtService = jwtService;
    }
    @Override
    // authentication : 로그인 성공한 사용자 정보(Spring Security가 만들어줌)
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        // username, role
        String username = authentication.getName();
        String role = authentication.getAuthorities().iterator().next().getAuthority();

        //JWT(Refresh) 발급
        // 소셜 로그인 성공 시 refresh token은 HttpOnly 쿠키로 전달하기 위해 발급
        // access token은 이후 별도 요청에서 헤더용으로 발급하는 구조
        String refreshToken = JWTUtil.createJWT(username, role, false);

        // 발급한 Refresh Token DB 저장(Refresh whitelist)
        jwtService.addRefresh(username, refreshToken);

        //응답
        Cookie refreshCookie = new Cookie("refreshToken", refreshToken);
        refreshCookie.setHttpOnly(true);    //httponly 옵션 설정하여 XSS공격 방지
        refreshCookie.setSecure(false); // https/http 모두 쿠키를 전송하도록 하는 옵션(실무에서는 true를 써서 https에서만 전송되도록 제한)
        refreshCookie.setPath("/"); // 모든 요청에서 쿠키 사용
        refreshCookie.setMaxAge(10);    // 10초 (프론트에서 발급 후 바로 헤더 전환 로직 진행 예정)

        response.addCookie(refreshCookie);
        response.sendRedirect("http://localhost:5173/cookie");

    }
}
