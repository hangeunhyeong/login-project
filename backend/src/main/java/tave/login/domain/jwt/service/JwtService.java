package tave.login.domain.jwt.service;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tave.login.domain.jwt.dto.JWTResponseDTO;
import tave.login.domain.jwt.dto.RefreshRequestDTO;
import tave.login.domain.jwt.entity.RefreshEntity;
import tave.login.domain.jwt.repository.RefreshRepository;
import tave.login.util.JWTUtil;

@Service
public class JwtService {
    private final RefreshRepository refreshRepository;

    public JwtService(RefreshRepository refreshRepository) {
        this.refreshRepository = refreshRepository;
    }

    // 소셜 로그인 성공 후 쿠키에 있던 refresh token을 꺼내서 검증한 뒤, 새로운 access 토큰, refresh 토큰을 응답 헤더에 담아 준다(refresh를 한번 쓰면 폐기하는 구조)
    // 소셜 로그인 직후 1회 실행되는 초기 토큰 교환 함수(소셜로그인 핸들러에서 jwt생성 후 쿠키에 담기->프론트로 redirect->jwt exchange api->cookie2header->로컬스토리지에 refreshtoken, access token 저장)
    // 이렇게 브라우저에 refresh쿠키를 저장시키고 access 토큰을 발급하는 이유는 소셜로그인 성공과 access 토큰 발급을 분리하기 위함이다
    @Transactional
    public JWTResponseDTO cookie2Header(HttpServletRequest request, HttpServletResponse response) {
        // 쿠키리스트
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            throw new RuntimeException("쿠키가 존재하지 않습니다");
        }

        // Refresh Token 획득
        String refreshToken = null;
        for (Cookie cookie : cookies) {
            if ("refreshToken".equals(cookie.getName())) {
                refreshToken = cookie.getValue();
                break;
            }
        }

        if (refreshToken == null) {
            throw new RuntimeException("refreshToken 쿠키가 없습니다.");
        }

        // Refresh 토큰 검증
        Boolean isValid = JWTUtil.isValid(refreshToken, false);
        if (!isValid) {
            throw new RuntimeException("유효하지 않은 refreshToken입니다.");
        }

        // 정보 추출
        String username = JWTUtil.getUsername(refreshToken);
        String role = JWTUtil.getRole(refreshToken);

        // 토큰 생성
        String newAccessToken = JWTUtil.createJWT(username, role, true);
        String newRefreshToken = JWTUtil.createJWT(username, role, false);

        // 기존 Refresh 토큰 DB삭제 후 신규추가
        RefreshEntity newRefreshEntity = RefreshEntity.builder()
                .username(username)
                .refresh(newRefreshToken)
                .build();

        removeRefresh(refreshToken);
        refreshRepository.flush();  // 같은 트랜잭션 내부라 : 삭제 -> 생성 문제 해결(flush를 하지 않으면 delete, insert 순서 보장 안됨)
        refreshRepository.save(newRefreshEntity);

        // 기존 쿠키 제거(기존 쿠키와 동일한 조건(path, secure)을 맞춰줘야 정확히 삭제됨)
        Cookie refreshCookie = new Cookie("refreshToken", null);
        refreshCookie.setHttpOnly(true);
        refreshCookie.setSecure(false);
        refreshCookie.setPath("/");
        refreshCookie.setMaxAge(10);
        response.addCookie(refreshCookie);

        return new JWTResponseDTO(newAccessToken, newRefreshToken);

    }

    // Refresh 토큰으로 Access 토큰 재발급 로직(rotate 포함)
    @Transactional
    public JWTResponseDTO refreshRotate(RefreshRequestDTO dto) {
        String refreshToken = dto.getRefreshToken();

        // Refresh 토큰 검증
        Boolean isValid = JWTUtil.isValid(refreshToken, false);
        if (!isValid) {
            throw new RuntimeException("유효하지 않은 refreshToken입니다.");
        }

        // RefreshEntity 존재 확인
        if (!existsByRefresh(refreshToken)) {
            throw new RuntimeException("유효하지 않은 refreshToken입니다.");
        }

        // 정보 추출
        String username = JWTUtil.getUsername(refreshToken);
        String role = JWTUtil.getRole(refreshToken);

        // 토큰 생성
        String newAccessToken = JWTUtil.createJWT(username, role, true);
        String newRefreshToken = JWTUtil.createJWT(username, role, false);

        // 기존 Refresh 토큰 DB 삭제 후 신규추가
        RefreshEntity newRefreshEntity = RefreshEntity.builder()
                .username(username)
                .refresh(newRefreshToken)
                .build();

        removeRefresh(refreshToken);
        refreshRepository.flush();
        refreshRepository.save(newRefreshEntity);

        return new JWTResponseDTO(newAccessToken, newRefreshToken);

    }

    // JWT Refresh 토큰 발급 후 저장 메소드
    @Transactional
    public void addRefresh(String username, String refreshToken) {
        RefreshEntity entity = RefreshEntity.builder()
                .username(username)
                .refresh(refreshToken)
                .build();
        refreshRepository.save(entity);
    }

    // JWT Refresh 존재 확인 메소드
    @Transactional(readOnly = true)
    public Boolean existsByRefresh(String refreshToken){
        return refreshRepository.existsByRefresh(refreshToken);
    }

    // JWT Refresh 토큰 기반 삭제 메소드
    @Transactional
    public void removeRefresh(String refreshToken) {
        refreshRepository.deleteByRefresh(refreshToken);
    }

    // 특정 유저 Refresh 토큰 모두 삭제 (탈퇴시)
    @Transactional
    public void removeRefreshUser(String username) {
        refreshRepository.deleteByUsername(username);
    }
}
