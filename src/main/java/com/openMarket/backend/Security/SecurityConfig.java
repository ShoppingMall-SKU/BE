package com.openMarket.backend.Security;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.openMarket.backend.JWT.JwtFilter;
import com.openMarket.backend.JWT.JwtService;
import com.openMarket.backend.Login.CustomLoginFilter;
import com.openMarket.backend.Login.LoginFailureHandler;
import com.openMarket.backend.Login.LoginService;
import com.openMarket.backend.User.User;
import com.openMarket.backend.User.UserRepository;
import io.jsonwebtoken.Jwt;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JwtService jwtService;

//    private final LoginSuccessHandler loginSuccessHandler1;
//    private final LoginFailureHandler loginFailureHandler1;


    public SecurityConfig(JwtService jwtService) {
        this.jwtService = jwtService;
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(httpSecuritySessionManagementConfigurer ->
                        httpSecuritySessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                .authorizeHttpRequests(authorizationManagerRequestMatcherRegistry ->
                        authorizationManagerRequestMatcherRegistry
                                .requestMatchers("/","/css/**","/images/**","/js/**","/favicon.ico","/h2-console/**","/static/**").permitAll()
                                //.requestMatchers("/api/product/**").permitAll()
//                                .requestMatchers("/api/product/list/{name}").permitAll()
                                .requestMatchers("/api/product/list").permitAll()
//                                .requestMatchers("/api/product/list/search").permitAll()
//                                .requestMatchers("/api/product/detail/{id}").permitAll()
                                .requestMatchers("/api/user/login").permitAll()
                                .requestMatchers("/api/user/signup").permitAll()
                                .anyRequest().authenticated()
                )


                .addFilterBefore(new JwtFilter(jwtService), UsernamePasswordAuthenticationFilter.class);



        return http.build();
    }

    @Bean
    public static BCryptPasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }



}



