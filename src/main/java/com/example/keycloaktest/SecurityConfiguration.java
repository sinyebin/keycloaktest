package com.example.keycloaktest;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers("/signup").permitAll() // 회원가입 경로에 대한 접근 허용
                        .requestMatchers("/admin/**").hasRole("ADMIN") // ADMIN 역할을 가진 사용자만 접근 가능
                        .requestMatchers("/user/**").hasRole("USER") // USER 역할을 가진 사용자만 접근 가능
                        .anyRequest().authenticated() // 나머지 요청은 모두 인증이 필요함
                )
                .oauth2Login(withDefaults()) // OAuth2 로그인 활성화
                // OAuth2 리소스 서버 설정 (JWT 토큰 사용)
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(withDefaults())
                )

                // CSRF 설정 비활성화 (REST API의 경우 필요할 수 있음)
                .csrf(csrf -> csrf.disable());

        return http.build();
    }
}