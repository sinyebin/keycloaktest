package com.example.keycloaktest;

import static org.springframework.security.config.Customizer.withDefaults;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {
    @Value("${user.redirect}")
    private String redirect;

    @Value("${keycloak.auth-server-url}")
    private String authServerUrl;

    @Value("${keycloak.realm}")
    private String realm;


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers("/signup").permitAll() // 회원가입 경로에 대한 접근 허용
                        .requestMatchers("/admin/**").hasRole("ADMIN") // ADMIN 역할을 가진 사용자만 접근 가능
                        .requestMatchers("/user/**").hasRole("USER") // USER 역할을 가진 사용자만 접근 가능
                        .anyRequest().authenticated() // 나머지 요청은 모두 인증이 필요함
                )
                .oauth2Login(oauth2Login -> oauth2Login
                        .defaultSuccessUrl("/", true)) // OAuth2 로그인 활성화
                // OAuth2 리소스 서버 설정 (JWT 토큰 사용)
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(withDefaults())
                )// 로그아웃 설정 추가
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessHandler((request, response, authentication) -> {
                            String idTokenHint = null;

                            if (authentication instanceof OAuth2AuthenticationToken) {
                                OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
                                OidcUser oidcUser = (OidcUser) oauthToken.getPrincipal();
                                idTokenHint = oidcUser.getIdToken().getTokenValue();
                            }

                            if (idTokenHint != null) {
                                String logoutUrl = authServerUrl + "realms/" + realm +
                                        "/protocol/openid-connect/logout?post_logout_redirect_uri=" +
                                        URLEncoder.encode(redirect, StandardCharsets.UTF_8.toString()) +
                                        "&id_token_hint=" + idTokenHint;

                                response.sendRedirect(logoutUrl);
                            } else {
                                // ID 토큰이 없는 경우의 처리
                                String logoutUrl = authServerUrl + "realms/" + realm +
                                        "/protocol/openid-connect/logout";
                                response.sendRedirect(logoutUrl);
                            }

                        })
                )
        // CSRF 설정 비활성화 (REST API의 경우 필요할 수 있음)
                .csrf(csrf -> csrf.disable());

        return http.build();
    }
    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(
                Arrays.asList("https://okrbiz.com","https://localhost:8443"));
        configuration.setAllowedMethods(Arrays.asList("GET","POST", "PUT", "DELETE"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}