package tave.login.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import tave.login.domain.jwt.service.JwtService;
import tave.login.util.JWTUtil;

import java.io.IOException;

@Component
@Qualifier("LoginSuccessHandler")   // 같은 타입 Bean이 여러개있을 때 어떤 Bean을 쓸지 지정하는 이름표(구현체가 여러개일경우 같은 타입 Bean이 여러개임)
public class LoginSuccessHandler implements AuthenticationSuccessHandler {
    private final JwtService jwtService;

    public LoginSuccessHandler(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    // authentication : 로그인 성공한 사용자 정보(Spring Security가 만들어줌)
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        // username, role
        String username = authentication.getName();
        String role = authentication.getAuthorities().iterator().next().getAuthority(); // 사용자의 권한목록을 가져온 후 그중 하나를 꺼내서 문자열로 변환

        // JWT(Access/Refresh) 발급
        String accessToken = JWTUtil.createJWT(username, role, true);
        String refreshToken = JWTUtil.createJWT(username, role, false);

        // 발급한 Refresh Token DB 저장(Refresh Whitelist)
        jwtService.addRefresh(username, refreshToken);

        // 응답
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        String json = String.format("{\"accessToken\":\"%s\", \"refreshToken\":\"%s\"}", accessToken, refreshToken);
        response.getWriter().write(json);
        response.getWriter().flush();
    }
}
