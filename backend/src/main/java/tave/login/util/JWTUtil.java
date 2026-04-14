package tave.login.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

public class JWTUtil {
    private static final SecretKey secretKey;
    private static final Long accessTokenExpiresIn; // accessToken 생명주기
    private static final Long refreshTokenExpiresIn;    // refreshToken 생명주기
    static  {
        String secretKeyString = "himynameiskimjihunmyyoutubechann";
        secretKey = new SecretKeySpec(secretKeyString.getBytes(StandardCharsets.UTF_8), Jwts.SIG.HS256.key().build().getAlgorithm());

        accessTokenExpiresIn = 3600L * 1000; // 1시간
        refreshTokenExpiresIn = 604800L * 1000; // 7일
    }

    // JWT 생성(Access/Refresh) : isAccess가 true이면 access 토큰, false이면 refresh 토큰 발급
    public static String createJWT(String username, String role, Boolean isAccess){
        long now = System.currentTimeMillis();
        long expiry = isAccess ? accessTokenExpiresIn : refreshTokenExpiresIn;
        String type = isAccess ? "access" : "refresh";

        return Jwts.builder()
                .claim("sub", username) // payload에 이름 추가
                .claim("role", role)    // payload에 role 추가
                .claim("type", type)    // payload에 type 추가
                .issuedAt(new Date(now))
                .expiration(new Date(now + expiry))
                .signWith(secretKey)
                .compact(); // JWT를 문자열로 변환
    }

    // JWT 유효 여부 (위조, 시간, Access/Refresh 여부)
    public static Boolean isValid(String token, Boolean isAccess) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(secretKey)  // secretKey를 parser에 등록(검증 방식/키 지정)
                    .build()    // parser 생성
                    .parseSignedClaims(token)   // JWT 분리, signature 검증, 만료시간 검증, payload JSON 파싱
                    .getPayload();  // payload 획득

            String type = claims.get("type", String.class);
            if(type == null)    return false;
            if(isAccess && !type.equals("access"))  return false;
            if(!isAccess && !type.equals("refresh"))    return false;

            return true;
        } catch (JwtException | IllegalArgumentException e) {   // 토큰 만료일 경우 JwtException
            return false;
        }
    }

    // JWT 클레임 username 파싱
    public static String getUsername(String token){
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("sub", String.class);
    }

    public static String getRole(String token) {
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role", String.class);
    }
}
