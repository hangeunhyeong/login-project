package tave.login.handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.util.StringUtils;
import tave.login.domain.jwt.service.JwtService;
import tave.login.util.JWTUtil;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

// SecurityConfig의 filterChain에서 new로 직접생성하고있기때문에 @Componenet, @Qualifier 설정 안해줘도됨!!
@AllArgsConstructor
public class RefreshTokenLogoutHandler implements LogoutHandler {
    private final JwtService jwtService;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        try {
            // 요청의 body를 문자열로 읽어오는 코드
            String body = new BufferedReader(new InputStreamReader(request.getInputStream()))
                    .lines().reduce("", String::concat);

            if (!StringUtils.hasText(body)) return;

            ObjectMapper mapper = new ObjectMapper();
            JsonNode jsonNode = mapper.readTree(body);
            String refreshToken = jsonNode.has("refreshToken") ? jsonNode.get("refreshToken").asText() : null;

            // 유효성 검증
            if (refreshToken == null) return;
            Boolean isValid = JWTUtil.isValid(refreshToken, false);
            if (!isValid) return;

            // Refresh 토큰 삭제
            jwtService.removeRefresh(refreshToken);
        } catch (IOException e) {
            throw new RuntimeException("Failed to read refresh token", e);
        }
    }

}
