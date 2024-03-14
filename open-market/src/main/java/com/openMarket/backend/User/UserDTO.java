package com.openMarket.backend.User;


import com.fasterxml.jackson.annotation.JsonCreator;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UserDTO {
    @NotBlank(message = "이름은 필수 입력 사항 입니다.")
    private String name;

    @NotBlank(message = "비밀번호를 입력하십시오.")
    private String password;

    private String phone;

    @NotBlank(message = "이메일을 입력하십시오.")
    @Email(message = "올바른 이메일 형식이 아닙니다.")
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
