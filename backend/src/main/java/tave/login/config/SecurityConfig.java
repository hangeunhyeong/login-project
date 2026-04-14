package tave.login.config;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import tave.login.domain.jwt.service.JwtService;
import tave.login.domain.user.entity.UserRoleType;
import tave.login.filter.JWTFilter;
import tave.login.filter.LoginFilter;
import tave.login.handler.RefreshTokenLogoutHandler;

import java.util.List;
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    private final AuthenticationConfiguration authenticationConfiguration;
    private final AuthenticationSuccessHandler loginSuccessHandler;
    private final AuthenticationSuccessHandler socialSuccessHandler;
    public SecurityConfig(AuthenticationConfiguration authenticationConfiguration,
                          @Qualifier("LoginSuccessHandler")AuthenticationSuccessHandler loginSuccessHandler,
                          @Qualifier("SocialSuccessHandler")AuthenticationSuccessHandler socialSuccessHandler) {
        this.authenticationConfiguration = authenticationConfiguration;
        this.loginSuccessHandler = loginSuccessHandler;
        this.socialSuccessHandler = socialSuccessHandler;
    }
    // 커스텀 자체 로그인 필터를 위한 AuthenticationManager Bean 수동 등록
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    // 비밀번호 단방향(BCrypt) 암호화용 Bean
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // SecurityFilterChain
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, JwtService jwtService) throws Exception {
        // CSRF 보안 필터 disable(stateless 서버이기 때문)
        http
                .csrf(AbstractHttpConfigurer::disable);
        // CORS 설정
        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()));
        // 기본 Form 기반 인증 필터들 disable : Spring이 기본 제공하는 세션 + 쿠키 기반 로그인을 안쓰겠다
        http
                .formLogin(AbstractHttpConfigurer::disable);

        // 기본 Basic 인증 필터 disable : HTTP Basic - 매번 요청헤더에 아이디/비밀번호를 실어보내는 방식(JWT는 로그인한 후에는 토큰만 실어보낸다)
        http
                .httpBasic(AbstractHttpConfigurer::disable);

        // OAuth2 인증용 : 소셜 로그인 관련 필터 활성화(Spring Security의 OAuth2 로그인 기능 활성화)
        http
                .oauth2Login(oauth2 -> oauth2
                        .successHandler(socialSuccessHandler));

        // 인가
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/jwt/exchange", "jwt/refresh").permitAll()    // 토큰을 재발급받으려고 호출하는 API인데 그 API에 access인증을 요구하면 안되므로 permitAll
                        .requestMatchers(HttpMethod.POST, "/user/exist", "/user").permitAll()
                        .requestMatchers(HttpMethod.GET, "/user").hasRole(UserRoleType.USER.name()) // user권한 있어야함(인증도 필요)
                        .requestMatchers(HttpMethod.PUT, "/user").hasRole(UserRoleType.USER.name())
                        .requestMatchers(HttpMethod.DELETE, "/user").hasRole(UserRoleType.USER.name())
                        .anyRequest().authenticated()   // 이외의 api요청에 대해서는 인증이 필요
                );


        // 예외 처리
        http
                .exceptionHandling(e -> e
                        .authenticationEntryPoint((request, response, authException) -> {
                            response.sendError(HttpServletResponse.SC_UNAUTHORIZED); // 401 응답
                        })
                        .accessDeniedHandler((request, response, authException) -> {
                            response.sendError(HttpServletResponse.SC_FORBIDDEN); // 403 응답
                        })
                );

        //커스텀 필터 추가
        http
                .addFilterBefore(new JWTFilter(), LogoutFilter.class);
        http
                .addFilterBefore(new LoginFilter(authenticationManager(authenticationConfiguration), loginSuccessHandler), UsernamePasswordAuthenticationFilter.class);


        // 세션 필터 설정 (STATELESS) : 세션 사용 안함
        http
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // 로그아웃 핸들러 설정(로그아웃 필터는 기본으로 적용되어있음)
        http
                .logout(logout -> logout
                        .addLogoutHandler(new RefreshTokenLogoutHandler(jwtService)));


        return http.build();
    }

    // CORS 설정
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("http://localhost:5173"));
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("*"));  // 클라이언트가 보내는 요청헤더는 전부 허용
        configuration.setExposedHeaders(List.of("Authorization", "Set-Cookie"));    // 브라우저의 프론트 코드가 읽기 가능한 응답헤더
        configuration.setMaxAge(3600L); // preflight 요청 결과를 1시간동안 브라우저가 캐시

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration); // 모든 URL에 동일한 CORS 규칙 적용
        return source;
    }

    // 권한 계층 - Security가 가지고 있는 role인 ADMIN, USER에 대해 계층을 부여
    @Bean
    public RoleHierarchy roleHierarchy() {
        return RoleHierarchyImpl.withRolePrefix("ROLE_")
                .role(UserRoleType.ADMIN.name()).implies(UserRoleType.USER.name())
                .build();
    }
}
