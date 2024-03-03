package com.openMarket.backend.User;


import com.fasterxml.jackson.annotation.JsonCreator;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;
import com.openMarket.backend.User.User.*;

@Getter
@Setter
public class UserDTO {
    @NotBlank(message = "이름은 필수 입력 사항 입니다.")
    private String name;

    @NotBlank(message = "")
    private String password;

    private String phone;

    @NotBlank(message = "")
    private String email;

    private String address;

    @JsonCreator
    public UserDTO (User user) {
        this.name = user.getName();
        this.email = user.getEmail();
        this.password = user.getPassword();
        this.address = user.getAddress();
        this.phone = user.getPhone();
    }

}
