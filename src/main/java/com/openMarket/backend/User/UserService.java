package com.openMarket.backend.User;

import com.openMarket.backend.JWT.JwtService;
import com.openMarket.backend.JWT.JwtToken;
import com.openMarket.backend.Security.SecurityConfig;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import com.openMarket.backend.User.User.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;


import java.util.Collection;
import java.util.List;
import java.util.Optional;

@RequiredArgsConstructor
@Service
@Transactional
@Slf4j
public class UserService {

    private final UserRepository userRepository;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final JwtService jwtService;
    private final BCryptPasswordEncoder encoder;
    private final List<GrantedAuthority> authorityList;

    public void signUp (String name, String password, String phone, String email, String address) {
        User user = new User();
        user.setName(name);
        user.setPassword(password);
        user.setPhone(phone);
        user.setEmail(email);
        user.setAddress(address);
        user.setRole(role.ROLE_USER);


        userRepository.save(user);
    }


    @Transactional
    public JwtToken login(HttpServletRequest request, String name, String pw, role role) {
        log.info("로그인 시도");
        Optional<User> user = userRepository.findByName(name);
        authorityList.add(new SimpleGrantedAuthority(role.name()));
        if (user.isPresent()) {
            String accessToken = jwtService.extractAccessToken(request);
            String refreshToken = user.get().getRefreshToken();
            if (!jwtService.validateToken(accessToken) || accessToken == null) { // access token 이 유효 x
                if (refreshToken != null) {
                    if (!jwtService.validateToken(refreshToken)) { // refresh token 이 유효하지 않을 때 둘 다 생성.
                        log.info("refresh token 만료. 재 생성 중....");
                        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(name, pw, authorityList);
                        Authentication authentication = authenticationManagerBuilder.getObject()
                                .authenticate(authenticationToken);
                        JwtToken token = jwtService.generateToken(authentication, user.get(), role);
                        log.info("Access Token and Refresh Token are created : {}", token);
                        return token;
                    } else { // refresh token 이 유효 하면 그대로 access token 만 생성 - access token 유효한지 체크

                        log.info("refresh token 이 유효합니다");
                        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(name, pw, authorityList);
                        Authentication authentication = authenticationManagerBuilder.getObject()
                                .authenticate(authenticationToken);
                        JwtToken token = jwtService.generateAccessToken(authentication, user.get(), role);
                        log.info("Only access Token is created : {}", token);
                        log.info(SecurityContextHolder.getContext().getAuthentication().toString());
                        return token;
                    }
                } else {

                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(name, pw, authorityList);
                    //System.out.println(authenticationToken.getAuthorities().toString() + "\n" + authenticationToken.getCredentials());
                    Authentication authentication = authenticationManagerBuilder.getObject()
                            .authenticate(authenticationToken);
                    JwtToken token = jwtService.generateToken(authentication, user.get(), role);
                    log.info("DB: access Token and refresh Token are created : {}", token);
                    return token;
                }
            }
            else { // access token이 유효
                log.info("토큰이 모두 유효 하므로 토큰 생성을 하지 않습니다.");
                    return JwtToken.builder()
                            .grantType("Bearer")
                            .accessToken(accessToken)
                            .refreshToken(refreshToken)
                            .build();
            }
        }
        else {
            throw new RuntimeException("User not found");
        }
    }

    @Transactional
    public void logout(HttpServletRequest request) {
        Optional<User> user = userRepository.findByName(request.getUserPrincipal().getName());
        if (user.isPresent()) {
            String accessToken = jwtService.extractAccessToken(request);
            String refreshToken = user.get().getRefreshToken();
            if (jwtService.validateToken(accessToken) && jwtService.validateToken(refreshToken)) {
                user.get().setRefreshToken(null);
            }
            else {
                throw new JwtException("Valid token");
            }
        }
        else {
            throw new RuntimeException("Data not found");
        }
    }

    public void delete (User user) {
        userRepository.delete(user);
    }

    public void update (User user, String nickname, String name) {
        //user.setNickname(nickname);
        user.setName(name);
        userRepository.save(user);
    }

    public void updateRefreshToken(User user, String refreshToken) {
        user.setRefreshToken(refreshToken);
        userRepository.save(user);
    }

    public void modifyPassword(User user, String pw) {
        //user.setPw(pw);
        userRepository.save(user);
    }

    public void modifyName(User user, String name) {
        user.setName(name);
        userRepository.save(user);
    }



    public User readByName (String name) {
        Optional<User> user = userRepository.findByName(name);
        if (user.isPresent()) {
            return user.get();
        }
        else {
            throw new RuntimeException("data not found");
        }
    }

//    public User readByNickname(String nickname) {
//        return userRepository.findByNickname(nickname);
//    }

    public List<User> readAll() {
        return userRepository.findAll();
    }

    public List<User> readByRole(User.role role) {
        return userRepository.findByRole(role);
    }

    public boolean existByName(String name) {
        return userRepository.findByName(name).isPresent();
    }

    public boolean existByEmail(String email) {
        return userRepository.findByEmail(email).isPresent();
    }

}
