package com.openMarket.backend.User;


import com.fasterxml.jackson.annotation.JsonCreator;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.jackson.JsonComponent;

@Getter
@Setter
@JsonComponent
public class UserLoginDTO {

    private String email;
    private String password;
}
