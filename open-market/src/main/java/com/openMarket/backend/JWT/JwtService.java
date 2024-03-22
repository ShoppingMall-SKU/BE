package com.openMarket.backend.JWT;

import com.openMarket.backend.User.User.role;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.xml.bind.DatatypeConverter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.security.Key;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

@Slf4j
@Component
public class JwtService {

    private final Key key;

    public JwtService(@Value("${jwt.secret.key}") String secretKey) {
        byte[] secretByteKey = DatatypeConverter.parseBase64Binary(secretKey);
        this.key = Keys.hmacShaKeyFor(secretByteKey);
        //this.userRepository = userRepository;
    }


    public JwtToken generateToken(Authentication authentication, role role) {

        log.info("토큰 생성.....");


        String accessToken = Jwts.builder() // 액세스 토큰
                .setSubject(authentication.getName()) // 액세스 토큰의 제목 설정 (메타데이터)
                .claim("auth", role.name())
                .setExpiration(new Date(System.currentTimeMillis() + (1000 * 10 * 60))) // 30분 만료기한
                .signWith(this.key, SignatureAlgorithm.HS256) // 암호화
                .compact(); // 문자열 직렬화하여 빌드

        String refreshToken = Jwts.builder()
                .setExpiration(new Date(System.currentTimeMillis() + (1000 * 30 * 60 * 36))) // 3일 만료기한
                .signWith(this.key, SignatureAlgorithm.HS256) // 암호화
                .compact(); // 직렬화


        log.info("토큰 발급 성공 !");
        log.info(accessToken);

        return JwtToken.builder()
                .grantType("Bearer")
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }


    public String generateAccessToken(String email, role role) {

        String accessToken = Jwts.builder()
                .setSubject(email)
                .claim("auth", role)
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 10 * 60))
                .signWith(this.key,SignatureAlgorithm.HS256)
                .compact();


        return accessToken;
    }



    public Authentication getAuthentication(String accessToken) {
        Claims claims = parseClaims(accessToken);

        if (claims.get("auth") == null) { // auth 밸류 값 비어 있으면 인증 안됨
            throw new RuntimeException("유효하지 않은 토큰");
        }
        log.info("권한 요소 : {}", claims);
        log.info(String.valueOf((claims.getExpiration().getTime() - System.currentTimeMillis()) / 1000) + " seconds remain..");
        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get("auth").toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        UserDetails principal = new org.springframework.security.core.userdetails.User(claims.getSubject(), "", authorities);

        return new UsernamePasswordAuthenticationToken(principal, "", authorities);
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token); // 서명이랑 복호화한 값이 같으면 트루
            //log.info("토큰이 유효합니다");
            return true;
        } catch (SecurityException | MalformedJwtException | ExpiredJwtException | UnsupportedJwtException | IllegalArgumentException e){
            //log.info("유효하지 않은 토큰");
            return false;
        }
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

    public String getEmailFromToken(String accessToken) {
        return parseClaims(accessToken).getSubject();
    }

    public Date getExpirationFromToken(String token) {
        return parseClaims(token).getExpiration();
    }

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
