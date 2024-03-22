package com.openMarket.backend.User;


import com.openMarket.backend.JWT.JwtService;
import com.openMarket.backend.OAuth.OAuth2UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;

import org.springframework.web.bind.annotation.*;

import java.io.UnsupportedEncodingException;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
@Slf4j
public class UserController {
    private final UserService userService;
    private final OAuth2UserService oAuth2UserService;

    @PostMapping("/signup")
    public void signUp(@RequestBody UserDTO userDTO) {
        userService.signUp(userDTO.getName(), userDTO.getPassword(),userDTO.getPhone(),userDTO.getEmail(), userDTO.getAddress());
    }

    @GetMapping("/check/email/{email}")
    public ResponseEntity<Boolean> checkEmail(@PathVariable String email) {
        return ResponseEntity.ok(!userService.existByEmail(email));
    }

    @GetMapping("/check/name/{name}")
    public ResponseEntity<Boolean> checkName(@PathVariable String name) {
        return ResponseEntity.ok(userService.existByName(name));
    }


    @GetMapping("/detail/{name}")
    public ResponseEntity<User> readByName(@PathVariable String name) {
        return ResponseEntity.ok(userService.readByName(name));
    }

    @GetMapping("/redis/check")
    public void checkRedis(HttpServletRequest request) {
        userService.checkRedisValue(request);
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(HttpServletResponse response, @RequestBody UserLoginDTO userLoginDTO) throws UnsupportedEncodingException {
        //log.info("id : {}, pw : {}" , userLoginDTO.getEmail(), userLoginDTO.getPassword());
        String accessToken = userService.login(
                userLoginDTO.getEmail(),
                userLoginDTO.getPassword()
        );
        response.setHeader("Authorization", "Bearer " + accessToken);
        log.info(accessToken);
        return ResponseEntity.ok("success");
    }

    @GetMapping("/logout")
    public ResponseEntity<String> logout(HttpServletRequest request) {
        userService.logout(request);
        return ResponseEntity.ok("logout success");
    }

    @DeleteMapping("/{name}")
    public void deleteUser(@PathVariable String name) {
        userService.delete(userService.readByName(name));
    }

    @PatchMapping("/{name}")
    public void modifyUser(@RequestBody UserDTO userDTO) {
        User user = userService.readByName(userDTO.getName());
        //userService.modifyName(user, userDTO.getNickname());
    }

}
