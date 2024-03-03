//package com.openMarket.backend.Login;
//
//
//import com.openMarket.backend.JWT.JwtService;
//import com.openMarket.backend.User.UserRepository;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import lombok.RequiredArgsConstructor;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
//
//@Slf4j
//@RequiredArgsConstructor
//public class LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
//
//    private final JwtService jwtService;
//    private final UserRepository userRepository;
//
//    @Value("${jwt.access.expiration}")
//    private String accessTokenExpiration;
//
//    @Override
//    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
//                                        Authentication authentication) {
//        String name = extractUsername(authentication);
//        String accessToken = jwtService.createAccessToken(name);
//        String refreshToken = jwtService.createRefreshToken();
//
//        jwtService.sendAcceessTokenAndRefreshToken(response, accessToken, refreshToken);
//
//        userRepository.findByName(name)
//                .ifPresent(user -> {
//                    user.setRefreshToken(refreshToken);
//                    userRepository.saveAndFlush(user);
//                });
//
//        log.info("로그인 성공 : {}", name);
//        log.info("액세스 토큰 : {}", accessToken);
//        log.info("액세스 토큰 만료 기한 : {}", accessTokenExpiration);
//
//    }
//
//    private String extractUsername(Authentication authentication) {
//        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
//        return userDetails.getUsername();
//    }
//}
