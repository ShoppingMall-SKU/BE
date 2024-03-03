package com.openMarket.backend.Cart;


import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("/cart")
public class CartController {
    private final CartService cartService;

    @PostMapping("/carts") // test완
    public ResponseEntity<String> postCart(@RequestBody CartDto cartDto){
        cartService.createCart(cartDto.getUser(),
                cartDto.getProduct(), cartDto.getQuantity());
        return ResponseEntity.ok("Cart created successfully!");
    }

    @GetMapping("/user/{userId}") // test완
    public ResponseEntity<List<Cart>> getCartListByUserId(@PathVariable int userId){
        List<Cart> cartList = cartService.getList(userId);
        return ResponseEntity.ok(cartList);
    }
    // 수량 변경 메소드
    @PostMapping("/{id}")  // test 완
    public ResponseEntity<String> modifiedCart(@PathVariable int id, @RequestParam int quantity){
        cartService.modifiedCart(cartService.getCartById(id), quantity);
        return ResponseEntity.status(303)
                .location(URI.create("/cart/user/"+ cartService.getUserIdByCart(id)))
                .build();
    }
    // 삭제 버튼을 누를 경우 -> cartId와 userId로 조회하여 cart삭제
    @DeleteMapping("/{id}") // test 완
    public ResponseEntity<String> deleteCart(@PathVariable int id){
        int userId = cartService.getUserIdByCart(id);
        cartService.deleteCart(id);
        return ResponseEntity.status(303)
                .location(URI.create("/cart/user/"+ userId))
                .build();
    }

}
