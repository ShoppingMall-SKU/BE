package com.openMarket.backend.User;


import com.openMarket.backend.JWT.JwtToken;
import com.openMarket.backend.JWT.JwtService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
@Slf4j
public class UserController {
    private final UserService userService;
    private final JwtService jwtService;


    @PostMapping("/signup")
    public void signUp(@RequestBody UserDTO userDTO) {
        //userService.signUp(userDTO.getNickname(),userDTO.getName(),userDTO.getPw(),userDTO.getRole());

    }

    @GetMapping("/{name}")
    public ResponseEntity<User> readByName(@PathVariable String name) {
        return ResponseEntity.ok(userService.readByName(name));
    }

    @PostMapping("/login")
    public ResponseEntity<JwtToken> login(@RequestBody UserLoginDTO userLoginDTO, HttpServletRequest request) throws UnsupportedEncodingException {
        JwtToken token = userService.login(
                request,
                userLoginDTO.getName(),
                userLoginDTO.getPassword(),
                userLoginDTO.getRole()
        );


        return ResponseEntity.ok(token);
    }
    @GetMapping("/logout")
    public void logout(HttpServletRequest request) {
        userService.logout(request);
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
