package com.openMarket.backend.JWT;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.xml.bind.DatatypeConverter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.support.BeanDefinitionDsl;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import com.openMarket.backend.User.*;
import com.openMarket.backend.User.User.*;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;


import java.security.Key;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Component
public class JwtService {

    public static long TOKEN_EXPIRATION_TIME = 1000 * 30 * 60;


    private final Key key;

    public JwtService(@Value("${jwt.secret.key}") String secretKey) {
        byte[] secretByteKey = DatatypeConverter.parseBase64Binary(secretKey);
        this.key = Keys.hmacShaKeyFor(secretByteKey);
        //this.userRepository = userRepository;
    }


    public JwtToken generateToken(Authentication authentication, User user, role role) {

        log.info("토큰 생성.....");

        String accessToken = Jwts.builder() // 액세스 토큰
                .setSubject(authentication.getName()) // 액세스 토큰의 제목 설정 (메타데이터)
                .claim("auth", role.name()) // 클레임으로 auth 키 주입
                .setExpiration(new Date(System.currentTimeMillis() * 1000 * 30 * 60)) // 30분 만료기한
                .signWith(this.key, SignatureAlgorithm.HS256) // 암호화
                .compact(); // 문자열 직렬화하여 빌드

        String refreshToken = Jwts.builder()
                .setExpiration(new Date(System.currentTimeMillis() * 1000 * 30 * 60 * 36)) // 3일 만료기한
                .signWith(this.key, SignatureAlgorithm.HS256) // 암호화
                .compact(); // 직렬화
        user.setRefreshToken(refreshToken);

        log.info("토큰 발급 성공 !");

        return JwtToken.builder()
                .grantType("Bearer")
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }


    public JwtToken generateAccessToken(Authentication authentication, User user, role role) {
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        String accessToken = Jwts.builder()
                .setSubject(authentication.getName())
                .claim("auth", role)
                .setExpiration(new Date(System.currentTimeMillis() * 1000 * 30 * 60))
                .signWith(this.key,SignatureAlgorithm.HS256)
                .compact();

        String refreshToken = user.getRefreshToken();

        return JwtToken.builder()
                .grantType("Bearer")
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }



    public Authentication getAuthentication(String accessToken) {
        Claims claims = parseClaims(accessToken);

        if (claims.get("auth") == null) { // auth 밸류 값 비어 있으면 인증 안됨
            throw new RuntimeException("유효하지 않은 토큰");
        }
        log.info("권한 요소 : {}", claims);
        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get("auth").toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());
        UserDetails principal = new org.springframework.security.core.userdetails.User(claims.getSubject(), "", authorities);

        return new UsernamePasswordAuthenticationToken(principal, "", authorities);
    }

    public boolean validateToken(String token) {
        try {
            Jws claim = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token); // 서명이랑 복호화한 값이 같으면 트루
            log.info("토큰이 유효합니다");
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e){
            log.info("토큰이 유효하지 않음.");
        } catch (ExpiredJwtException e) {
            log.info("토큰이 만료됨.");
        } catch (UnsupportedJwtException e) {
            log.info("지원하지 않는 토큰 방식.");
        } catch (IllegalArgumentException e) {
            log.info("토큰이 비어있음.");
        }
        return false;
    }

    public String extractAccessToken(HttpServletRequest request) {
        String token = resolveToken(request);
        if (token != null) {
            return token;
        }
        else {
            return null;
        }
    }

    private String resolveToken(HttpServletRequest request) {
        String BearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(BearerToken) && BearerToken.startsWith("Bearer")) {
            BearerToken  = BearerToken.replace("Bearer ", "");
            return BearerToken;
        }
        return null;
    }
//    public User getUserFromToken(String token) {
//        try {
//            Jws claim = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
//            Optional<User> user = userRepository.findByName(claim.getBody().toString().split(",")[0].replace("{sub=", ""));
//            if(user.isPresent()) {
//                return user.get();
//            }
//            else {
//                log.info("유저가 존재하지 않음");
//                return null;
//            }
//        }  catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e){
//            log.info("토큰이 유효하지 않음.");
//        } catch (ExpiredJwtException e) {
//            log.info("토큰이 만료됨.");
//        } catch (UnsupportedJwtException e) {
//            log.info("지원하지 않는 토큰 방식.");
//        } catch (IllegalArgumentException e) {
//            log.info("토큰이 비어있음.");
//        }
//        return null;
//    }


    private Claims parseClaims(String accessToken) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(accessToken)
                    .getBody();
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        }
    }
}
