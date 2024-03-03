package com.openMarket.backend.JWT;


import lombok.*;
import org.springframework.stereotype.Component;

@AllArgsConstructor
@Data
@Builder
public class JwtToken {
    private String grantType;
    private String accessToken;
    private String refreshToken;
}
