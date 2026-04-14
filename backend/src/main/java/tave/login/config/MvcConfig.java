package tave.login.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
// Controller 들어가기 직전에 적용되는 CORS(SecuritConfig에서의 CORS 설정은 Security FilterChain 단계에서 적용되는 CORS)
// MvcConfig는 Security Filter이후에 실행되는 CORS 설정이니 MvcConfig 레벨에서의 CORS 설정은 필요없는것 아닌가?
// 필요하다 이유는 요청이 Security를 안거치고 MVC로 바로가는 경우가 있기 때문
@Configuration
public class MvcConfig implements WebMvcConfigurer {
    @Override
    public void addCorsMappings(CorsRegistry corsRegistry) {
        corsRegistry.addMapping("/**")
                .allowedOrigins("http://localhost:5173")
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                .allowCredentials(true)
                .allowedHeaders("*")    // 요청을 보낼 때 허용되는 헤더
                .exposedHeaders("Authorization", "Set-Cookie");

    }
}
