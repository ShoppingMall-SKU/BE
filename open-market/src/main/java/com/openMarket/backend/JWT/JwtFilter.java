package com.openMarket.backend.JWT;


import com.openMarket.backend.Redis.RedisConfig;
import com.openMarket.backend.User.User;
import com.openMarket.backend.User.UserRepository;
import com.openMarket.backend.User.UserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Slf4j
@Component
public class JwtFilter extends OncePerRequestFilter {

    private static final List<String> NO_CHECK_LIST = new ArrayList<>();
    private static final String NO_CHECK_URL = "/api/user/login";
    private static final String NO_CHECK_URL2 = "/api/user/signup";

    private static final String NO_CHECK_URL3 = "/api/product";

    private final JwtService jwtService;
    private final RedisConfig redisConfig;

    public JwtFilter(JwtService jwtService, RedisConfig redisConfig) {
        this.redisConfig = redisConfig;
        this.jwtService = jwtService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        String token = resolveToken(request);
        log.info("uri : {}", request.getRequestURI());

        if (request.getRequestURI().equals(NO_CHECK_URL) || request.getRequestURI().equals(NO_CHECK_URL2) || request.getRequestURI().contains(NO_CHECK_URL3)){
            filterChain.doFilter(request, response);
        }
        else {
            //log.info("토큰 확인중... {}", token);
            String email = jwtService.getEmailFromToken(token);

            if (jwtService.validateToken(token) && redisConfig.redisTemplate().opsForValue().get(email) != null) {
                Authentication authentication = jwtService.getAuthentication(token);
                SecurityContextHolder.getContext().setAuthentication(authentication);
                log.info("유저 : {}", email);
                log.info("토큰 인증 성공");
                filterChain.doFilter(request, response);
            } else if (!jwtService.validateToken(token) && email != null) { // access token 만료
                String refreshToken = redisConfig.redisTemplate().opsForValue().get(email);
                if (jwtService.validateToken(refreshToken)) { // refreh token 검증
                    String reIssuedToken = jwtService.generateAccessToken(email, User.role.ROLE_USER);
                    Authentication authentication = jwtService.getAuthentication(reIssuedToken);
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                    response.setHeader("Authorization","Bearer " + reIssuedToken);
                    log.info("액세스 토큰 자동 재생성");
                    filterChain.doFilter(request, response);
                } else {
                    log.info("토큰 인증 실패");
                    SecurityContextHolder.getContext().setAuthentication(null);
                    filterChain.doFilter(request, response);
                }
            } else {
                log.info("토큰 인증 실패");
                filterChain.doFilter(request, response);
            }
        }
        //filterChain.doFilter(request, response);
    }

    private String resolveToken(HttpServletRequest request) {
        String BearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(BearerToken) && BearerToken.startsWith("Bearer")) {
            BearerToken  = BearerToken.replace("Bearer ", "");
            return BearerToken;
        }
        return null;
    }

}
