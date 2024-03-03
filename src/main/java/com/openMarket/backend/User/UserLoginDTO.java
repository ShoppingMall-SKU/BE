package com.openMarket.backend.User;


import com.fasterxml.jackson.annotation.JsonCreator;
import lombok.Getter;
import lombok.Setter;
import com.openMarket.backend.User.User.role;

@Getter
@Setter
public class UserLoginDTO {
    private String name;
    private String password;
    private role role;

    @JsonCreator
    public UserLoginDTO(User user) {
        this.name = user.getName();
        this.password = user.getPassword();
        this.role = user.getRole();
    }
}
