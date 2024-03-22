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
                                .requestMatchers("/","/css/**","/images/**","/js/**","/favicon.ico","/static/**").permitAll()
                                .requestMatchers("/**").permitAll()


                                .anyRequest().authenticated()
                )


                .addFilterAfter(new JwtFilter(jwtService, redisConfig), UsernamePasswordAuthenticationFilter.class)
                .cors(cors -> cors.configurationSource(request -> corsConfigurationSource().getCorsConfiguration(request)));

        return http.build();
    }


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
        configuration.setExposedHeaders(List.of("Authorization")); // 없어도 무방할거 같은데

        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }
}



