package com.openMarket.backend.Cart;


import com.openMarket.backend.Product.Product;
import com.openMarket.backend.User.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class CartService {
    private final CartRepository cartRepository;

    //CRUD -> 장바구니

    // Create Cart
    public void createCart(User user, Product product, int quantity){
        Cart cart = new Cart();
        cart.setQuantity(quantity);
        cart.setUser(user); // 구매자
        cart.setProduct(product); // 판매 상품
        this.cartRepository.save(cart);
    }

    // Read Cart
    public List<Cart> getList(int id){
        return this.cartRepository.findByUserId(id);
    }

    // cartId로 Cart조회
    public Cart getCartById(int id){
        return this.cartRepository.findById(id);
    }

    // cartId로 userId 찾기
    public int getUserIdByCart(int cartId){
        Cart cart = getCartById(cartId);
        return  cart.getUser().getId();
    }

    // Update Cart
    public void modifiedCart(Cart cart, int quantity){
        cart.setQuantity(quantity);
        this.cartRepository.save(cart);
    }

    // Delete Cart
    public void deleteCart(int id){
        this.cartRepository.delete(getCartById(id));
    }

}
