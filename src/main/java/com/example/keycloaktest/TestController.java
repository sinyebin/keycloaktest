package com.example.keycloaktest;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.HashMap;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@Controller
public class TestController {




    @Autowired
    KeycloakUserService keycloakUserService;

    @GetMapping("/")
    public String index(Model model) {
        OAuth2AuthenticationToken authentication = (OAuth2AuthenticationToken) SecurityContextHolder.getContext().getAuthentication();

        OAuth2User user = authentication.getPrincipal();
        String loginType = authentication.getAuthorizedClientRegistrationId(); // "google" 또는 다른 클라이언트

        model.addAttribute("name", user.getAttribute("name"));
        model.addAttribute("email", user.getAttribute("email"));
        model.addAttribute("loginType", loginType);

        return "index";
    }


    @ResponseBody
    @GetMapping(path = "/unauthenticated")
    public HashMap unauthenticatedRequests() {
        return new HashMap(){{
            put("this is ", "unauthenticated endpoint");
        }};
    }

    @ResponseBody
    @GetMapping("/test")
    public Principal getUser(Principal principal) {
        // 사용자 정보 반환
        return principal;
    }

    @ResponseBody
    @PostMapping("/signup")
    public ResponseEntity<?> signUp(@RequestBody SignUpRequest signUpRequest) {
        System.out.println("1111"+signUpRequest.getUsername()+" "+ signUpRequest.getPassword());
        keycloakUserService.createUser(signUpRequest.getUsername(), signUpRequest.getPassword());
        return ResponseEntity.ok().build();
    }

//    @GetMapping("/custom_logout")
//    public String logout(HttpServletRequest request, HttpServletResponse response) {
//        System.out.println(111111);
//        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
//
//        if (auth != null) {
//            new SecurityContextLogoutHandler().logout(request, response, auth);
//        }
//        // Keycloak 로그아웃 엔드포인트로 리다이렉트
//        return "redirect:" + authServerUrl + "/realms/" + realm +
//                "/protocol/openid-connect/logout?redirect_uri=" + URLEncoder.encode(redirect, StandardCharsets.UTF_8);
//    }

    @GetMapping("/logout")
    public String logout() {
        // 실제 로그아웃 처리는 SecurityConfiguration에서 설정했습니다.
        // 이 메소드는 단지 엔드포인트를 제공하기 위함입니다.
        return "redirect:/";
    }
}
