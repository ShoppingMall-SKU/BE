package com.openMarket.backend.User;


import jakarta.persistence.*;
import lombok.Builder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

@Entity
@Setter
@Getter
@RequiredArgsConstructor
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    private String name;

    private String password; //비번

    private String phone;

    private String email;

    private String address;

    @Enumerated(value = EnumType.STRING)
    private role role;

    public enum role {
        ROLE_USER("사용자"),
        ROLE_ADMIN("관리자");

        private String role;

        role(String role) {this.role = role;}
    }

    private String refreshToken;

    //private providerType providerType;

    public enum providerType {
        GOOGLE("구글"),
        NORMAL("일반");

        private String pt;

        providerType(String providerType) {
            this.pt = providerType;
        }

        public String getProviderType() {
            return this.pt;
        }
    }

}
