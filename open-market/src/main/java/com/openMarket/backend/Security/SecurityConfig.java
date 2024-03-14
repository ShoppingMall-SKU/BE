package com.openMarket.backend.Security;


import com.openMarket.backend.JWT.JwtFilter;
import com.openMarket.backend.JWT.JwtService;
import com.openMarket.backend.OAuth.OAtuth2LoginFailureHandler;
import com.openMarket.backend.OAuth.OAuth2LoginSuccessHandler;
import com.openMarket.backend.OAuth.OAuth2UserService;
import com.openMarket.backend.Redis.RedisConfig;
import com.openMarket.backend.User.UserRepository;
import com.openMarket.backend.User.UserService;
import io.jsonwebtoken.Jwt;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.cache.CacheProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final RedisConfig redisConfig;
    private final UserService userService;
    private final OAuth2UserService oAuth2UserService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .httpBasic(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(httpSecuritySessionManagementConfigurer ->
                        httpSecuritySessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                .authorizeHttpRequests(authorizationManagerRequestMatcherRegistry ->
                        authorizationManagerRequestMatcherRegistry
                                .requestMatchers("/","/css/**","/images/**","/js/**","/favicon.ico","/h2-console/**","/static/**").permitAll()
                                .requestMatchers("/api/product/**").permitAll()
                                //.requestMatchers("/api/product/**").permitAll()
                                .requestMatchers("/api/user/login").permitAll()
                                .requestMatchers("/api/user/login/social").permitAll()
                                .requestMatchers("/oauth2/code/google").permitAll()
                                .requestMatchers("/oauth2/callback").permitAll()
                                .anyRequest().authenticated()
                )


//                .oauth2Login( o -> o.defaultSuccessUrl("/oauth2/code/google")
//                        .userInfoEndpoint(userService -> userService.userService(oAuth2UserService)))


                .addFilterAfter(new JwtFilter(jwtService, redisConfig), UsernamePasswordAuthenticationFilter.class)
                .cors(cors -> cors.configurationSource(request -> {
                CorsConfiguration configuration = new CorsConfiguration();
                configuration.setAllowedOrigins(List.of("http://localhost:3000"));
                configuration.setAllowedMethods(List.of("GET","POST","PUT","DELETE"));
                return configuration;
            }));


        return http.build();
    }

//    @Bean
//    protected void configure(HttpSecurity http) throws Exception {
//        http
//                .formLogin(AbstractHttpConfigurer::disable)
//                .httpBasic(AbstractHttpConfigurer::disable)
//                .csrf(AbstractHttpConfigurer::disable)
//                .sessionManagement(httpSecuritySessionManagementConfigurer ->
//                        httpSecuritySessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//
//                .oauth2Login( o -> o.defaultSuccessUrl("/oauth2/code/google")
//                        .userInfoEndpoint(userService -> userService.userService(oAuth2UserService)));
//
//
//    }


    @Bean
    public static BCryptPasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public OAuth2LoginSuccessHandler loginSuccessHandler() {
        return new OAuth2LoginSuccessHandler(jwtService, userRepository, userService);
    }

    @Bean
    public OAtuth2LoginFailureHandler loginFailureHandler() {
        return new OAtuth2LoginFailureHandler();
    }


    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        final CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("http://localhost:3000"));
        configuration.addAllowedHeader("*");
        configuration.addAllowedMethod("*");
        configuration.setAllowCredentials(true);

        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }
}



